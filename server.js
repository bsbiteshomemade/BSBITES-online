const express = require("express");
const crypto = require("crypto");
const path = require("path");
const Razorpay = require("razorpay");
require("dotenv").config();

const app = express();
app.use(express.json({limit:"100kb"}));
app.use(express.static(__dirname));

const PORT = process.env.PORT || 3000;
const KEY_ID = process.env.RAZORPAY_KEY_ID;
const KEY_SECRET = process.env.RAZORPAY_KEY_SECRET;
const GOOGLE_SCRIPT_URL = process.env.GOOGLE_SCRIPT_URL || "";
const FRONTEND_URL = process.env.FRONTEND_URL || "";
const SESSION_SECRET = process.env.SESSION_SECRET || "CHANGE_THIS_TO_A_LONG_RANDOM_SECRET";

app.use((req,res,next)=>{
  const origin=req.headers.origin;
  if(FRONTEND_URL && origin===FRONTEND_URL){
    res.setHeader("Access-Control-Allow-Origin",origin);
    res.setHeader("Vary","Origin");
    res.setHeader("Access-Control-Allow-Methods","GET,POST,OPTIONS");
    res.setHeader("Access-Control-Allow-Headers","Content-Type, Authorization");
  }
  if(req.method==="OPTIONS") return res.sendStatus(204);
  next();
});

const PRODUCTS={
  "Milk Chocolate":199,
  "Almond Crunch":249,
  "Kaju Makhana Royal Crunch":299
};

const razorpay=KEY_ID&&KEY_SECRET
  ?new Razorpay({key_id:KEY_ID,key_secret:KEY_SECRET})
  :null;

function cleanPhone(v){
  return String(v||"").replace(/\D/g,"");
}

function normalizeEmail(v){
  return String(v||"").trim().toLowerCase();
}

function calculateCart(cart){
  if(!Array.isArray(cart)||!cart.length)
    throw new Error("Cart is empty.");

  let total=0;
  const normalized=[];

  for(const item of cart){
    const name=String(item.name||"");
    const qty=Number(item.qty);

    if(
      !PRODUCTS[name]||
      !Number.isInteger(qty)||
      qty<1||
      qty>50
    ){
      throw new Error("Invalid product or quantity.");
    }

    total+=PRODUCTS[name]*qty;

    normalized.push({
      name,
      qty,
      price:PRODUCTS[name]
    });
  }

  return {total,normalized};
}

function hashPassword(password,salt){
  return crypto.scryptSync(password,salt,64).toString("hex");
}

function makeToken(customer){
  const payload={
    id:customer.id,
    name:customer.name,
    phone:customer.phone,
    email:customer.email||"",
    exp:Date.now()+1000*60*60*24*30
  };

  const raw=Buffer
    .from(JSON.stringify(payload))
    .toString("base64url");

  const sig=crypto
    .createHmac("sha256",SESSION_SECRET)
    .update(raw)
    .digest("base64url");

  return `${raw}.${sig}`;
}

function readToken(req){
  const h=req.headers.authorization||"";

  if(!h.startsWith("Bearer "))
    return null;

  const token=h.slice(7);
  const parts=token.split(".");

  if(parts.length!==2)
    return null;

  const [raw,sig]=parts;

  const expected=crypto
    .createHmac("sha256",SESSION_SECRET)
    .update(raw)
    .digest("base64url");

  if(
    sig.length!==expected.length ||
    !crypto.timingSafeEqual(
      Buffer.from(sig),
      Buffer.from(expected)
    )
  ){
    return null;
  }

  try{
    const p=JSON.parse(
      Buffer.from(raw,"base64url").toString("utf8")
    );

    if(!p.id||p.exp<Date.now())
      return null;

    return p;
  }catch{
    return null;
  }
}

function requireAuth(req,res,next){
  const c=readToken(req);

  if(!c){
    return res.status(401).json({
      error:"Please sign in to continue."
    });
  }

  req.customer=c;
  next();
}

async function sheet(action,data){
  if(!GOOGLE_SCRIPT_URL){
    throw new Error(
      "Google Sheets connection is not configured on the backend."
    );
  }

  const r=await fetch(
    GOOGLE_SCRIPT_URL,
    {
      method:"POST",
      headers:{
        "Content-Type":"text/plain;charset=utf-8"
      },
      body:JSON.stringify({
        action,
        ...data
      })
    }
  );

  const text=await r.text();

  let d={};

  try{
    d=JSON.parse(text);
  }catch{}

  if(
    !r.ok||
    d.ok===false
  ){
    throw new Error(
      d.error||
      `Google Sheets request failed (${r.status})`
    );
  }

  return d;
}

/* Razorpay public configuration */

app.get("/api/config",(req,res)=>{
  res.json({
    keyId:KEY_ID||""
  });
});

/* CUSTOMER REGISTRATION */

app.post("/api/auth/register",async(req,res)=>{
  try{
    const name=String(req.body.name||"").trim();
    const phone=cleanPhone(req.body.phone);
    const email=normalizeEmail(req.body.email);
    const password=String(req.body.password||"");

    if(
      !name||
      !/^[0-9]{10}$/.test(phone)||
      password.length<6
    ){
      return res.status(400).json({
        error:
          "Please enter your name, a valid 10-digit mobile number and a password of at least 6 characters."
      });
    }

    if(
      email&&
      !/^\S+@\S+\.\S+$/.test(email)
    ){
      return res.status(400).json({
        error:"Please enter a valid email address."
      });
    }

    const lookup=await sheet(
      "findCustomer",
      {identifier:phone}
    );

    if(lookup.customer){
      return res.status(409).json({
        error:
          "An account with this mobile number already exists. Please sign in."
      });
    }

    if(email){
      const byEmail=await sheet(
        "findCustomer",
        {identifier:email}
      );

      if(byEmail.customer){
        return res.status(409).json({
          error:
            "An account with this email already exists. Please sign in."
        });
      }
    }

    const salt=crypto
      .randomBytes(16)
      .toString("hex");

    const hash=hashPassword(
      password,
      salt
    );

    const customer={
      id:crypto.randomUUID(),
      name,
      phone,
      email,
      passwordSalt:salt,
      passwordHash:hash,
      createdAt:new Date().toISOString()
    };

    await sheet(
      "createCustomer",
      {customer}
    );

    const safe={
      id:customer.id,
      name,
      phone,
      email
    };

    res.json({
      token:makeToken(safe),
      customer:safe
    });

  }catch(e){
    console.error("register",e);

    res.status(500).json({
      error:e.message||
        "Could not create account."
    });
  }
});

/* CUSTOMER LOGIN */

app.post("/api/auth/login",async(req,res)=>{
  try{
    const identifier=
      String(req.body.identifier||"").trim();

    const password=
      String(req.body.password||"");

    if(!identifier||!password){
      return res.status(400).json({
        error:
          "Please enter your mobile/email and password."
      });
    }

    const lookup=await sheet(
      "findCustomer",
      {
        identifier:
          identifier.includes("@")
            ?normalizeEmail(identifier)
            :cleanPhone(identifier)
      }
    );

    const c=lookup.customer;

    if(!c){
      return res.status(401).json({
        error:
          "Account not found. Please check your details or create an account."
      });
    }

    const hash=hashPassword(
      password,
      c.passwordSalt||""
    );

    if(hash!==c.passwordHash){
      return res.status(401).json({
        error:"Incorrect password."
      });
    }

    const safe={
      id:c.id,
      name:c.name,
      phone:c.phone,
      email:c.email||""
    };

    res.json({
      token:makeToken(safe),
      customer:safe
    });

  }catch(e){
    console.error("login",e);

    res.status(500).json({
      error:e.message||
        "Could not sign in."
    });
  }
});

/* CURRENT CUSTOMER */

app.get(
  "/api/auth/me",
  requireAuth,
  (req,res)=>{
    res.json({
      customer:req.customer
    });
  }
);

/* CUSTOMER ORDER HISTORY */

app.get(
  "/api/orders",
  requireAuth,
  async(req,res)=>{
    try{
      const d=await sheet(
        "getOrders",
        {
          customerId:req.customer.id
        }
      );

      res.json({
        orders:d.orders||[]
      });

    }catch(e){
      console.error("orders",e);

      res.status(500).json({
        error:
          "Could not load your orders right now."
      });
    }
  }
);

/* CREATE RAZORPAY ORDER */

app.post(
  "/api/create-order",
  requireAuth,
  async(req,res)=>{
    try{
      if(!razorpay){
        return res.status(503).json({
          error:
            "Online payment is not configured yet."
        });
      }

      const {
        total,
        normalized
      }=calculateCart(req.body.cart);

      const customer=
        req.body.customer||{};

      const name=
        String(customer.name||"").trim();

      const phone=
        cleanPhone(customer.phone);

      const email=
        normalizeEmail(customer.email);

      const address=
        String(customer.address||"").trim();

      if(
        !name||
        !/^[0-9]{10}$/.test(phone)||
        !address
      ){
        return res.status(400).json({
          error:
            "Please provide a valid name, 10-digit phone number and delivery address."
        });
      }

      const order=
        await razorpay.orders.create({
          amount:total*100,
          currency:"INR",
          receipt:BSB-${Date.now()},
          notes:{
            customer_name:
              name.slice(0,255),

            customer_phone:
              phone,

            products:
              normalized
                .map(
                  x=>${x.name} x ${x.qty}
                )
                .join(", ")
                .slice(0,255)
          }
        });

      res.json({
        orderId:order.id,
        amount:order.amount,
        currency:order.currency
      });

    }catch(e){
      console.error(
        "create-order",
        e
      );

      res.status(400).json({
        error:
          e.message||
          "Could not create payment order."
      });
    }
  }
);

/* VERIFY PAYMENT + SAVE ORDER */

app.post(
  "/api/verify-payment",
  requireAuth,
  async(req,res)=>{
    try{
      if(!razorpay){
        return res.status(503).json({
          verified:false,
          error:
            "Online payment is not configured yet."
        });
      }

      const {
        razorpay_order_id,
        razorpay_payment_id,
        razorpay_signature
      }=req.body;

      if(
        !razorpay_order_id||
        !razorpay_payment_id||
        !razorpay_signature
      ){
        return res.status(400).json({
          verified:false,
          error:
            "Missing payment verification data."
        });
      }

      const expected=
        crypto
          .createHmac(
            "sha256",
            KEY_SECRET
          )
          .update(
            ${razorpay_order_id}|${razorpay_payment_id}
          )
          .digest("hex");

      if(expected!==razorpay_signature){
        return res.status(400).json({
          verified:false,
          error:
            "Payment signature verification failed."
        });
      }

      const payment=
        await razorpay.payments.fetch(
          razorpay_payment_id
        );

      if(
        payment.order_id!==razorpay_order_id||
        ![
          "captured",
          "authorized"
        ].includes(payment.status)
      ){
        return res.status(400).json({
          verified:false,
          error:
            "Payment is not in a valid state."
        });
      }

      const customer=
        req.body.customer||{};

      const {
        normalized
      }=calculateCart(
        req.body.cart
      );

      const phone=
        cleanPhone(customer.phone);

      const email=
        normalizeEmail(customer.email);

      const auth=req.customer;

      const orderData={
        orderId:
          razorpay_order_id,

        customerId:
          auth?auth.id:"",

        name:
          String(customer.name||"").trim(),

        phone,

        email,

        address:
          String(customer.address||"").trim(),

        products:
          normalized
            .map(
              x=>
                ${x.name} x ${x.qty} = ₹${x.price*x.qty}
            )
            .join(", "),

        quantity:
          normalized.reduce(
            (s,x)=>s+x.qty,
            0
          ),

        total:
          payment.amount/100,

        paymentStatus:
          "Razorpay - Verified",

        paymentId:
          razorpay_payment_id,

        status:
          "Confirmed",

        date:
          new Date().toISOString()
      };

      try{
        await sheet(
          "saveOrder",
          {order:orderData}
        );

      }catch(sheetErr){
        console.error(
          "Google Sheets saveOrder failed",
          sheetErr
        );

        return res.status(500).json({
          verified:false,
          error:
            "Payment was successful, but the order could not be saved. Please contact BS Bites with payment ID: "+
            razorpay_payment_id
        });
      }

      res.json({
        verified:true,
        paymentId:
          razorpay_payment_id,
        orderId:
          razorpay_order_id
      });

    }catch(e){
      console.error(
        "verify-payment",
        e
      );

      res.status(500).json({
        verified:false,
        error:
          "Could not verify the payment."
      });
    }
  }
);

/* HEALTH CHECK */

app.get(
  "/health",
  (req,res)=>{
    res.json({ok:true});
  }
);

app.listen(
  PORT,
  ()=>{
    console.log(
      BS Bites running on port ${PORT}
    );
  }
);
