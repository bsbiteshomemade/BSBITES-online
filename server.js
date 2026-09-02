const express = require("express");
const crypto = require("crypto");
const Razorpay = require("razorpay");

const app = express();

app.use(express.json({ limit: "100kb" }));
app.use(express.static(__dirname));

const PORT = process.env.PORT || 3000;

const KEY_ID = process.env.RAZORPAY_KEY_ID || "";
const KEY_SECRET = process.env.RAZORPAY_KEY_SECRET || "";
const GOOGLE_SCRIPT_URL = process.env.GOOGLE_SCRIPT_URL || "";
const FRONTEND_URL = process.env.FRONTEND_URL || "";

const SESSION_SECRET =
  process.env.SESSION_SECRET ||
  "BSBITES_CHANGE_THIS_TO_A_LONG_RANDOM_SECRET";


/* =========================================================
   PRODUCTS
========================================================= */

const PRODUCTS = {
  "Milk Chocolate": 199,
  "Almond Crunch": 249,
  "Kaju Makhana Royal Crunch": 299
};


/* =========================================================
   RAZORPAY
========================================================= */

const razorpay =
  KEY_ID && KEY_SECRET
    ? new Razorpay({
        key_id: KEY_ID,
        key_secret: KEY_SECRET
      })
    : null;


/* =========================================================
   CORS
========================================================= */

app.use((req, res, next) => {
  const origin = req.headers.origin;

  if (FRONTEND_URL && origin === FRONTEND_URL) {
    res.setHeader(
      "Access-Control-Allow-Origin",
      origin
    );

    res.setHeader("Vary", "Origin");

    res.setHeader(
      "Access-Control-Allow-Methods",
      "GET,POST,OPTIONS"
    );

    res.setHeader(
      "Access-Control-Allow-Headers",
      "Content-Type, Authorization"
    );
  }

  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }

  next();
});


/* =========================================================
   HELPERS
========================================================= */

function cleanPhone(value) {
  return String(value || "")
    .replace(/\D/g, "");
}


function normalizeEmail(value) {
  return String(value || "")
    .trim()
    .toLowerCase();
}


function calculateCart(cart) {
  if (!Array.isArray(cart) || cart.length === 0) {
    throw new Error("Cart is empty.");
  }

  let total = 0;
  const normalized = [];

  for (const item of cart) {
    const name = String(item.name || "");
    const qty = Number(item.qty);

    if (
      !PRODUCTS[name] ||
      !Number.isInteger(qty) ||
      qty < 1 ||
      qty > 50
    ) {
      throw new Error(
        "Invalid product or quantity."
      );
    }

    total += PRODUCTS[name] * qty;

    normalized.push({
      name: name,
      qty: qty,
      price: PRODUCTS[name]
    });
  }

  return {
    total: total,
    normalized: normalized
  };
}


/* =========================================================
   PASSWORD
========================================================= */

function hashPassword(password, salt) {
  return crypto
    .scryptSync(password, salt, 64)
    .toString("hex");
}


/* =========================================================
   LOGIN TOKEN
========================================================= */

function makeToken(customer) {
  const payload = {
    id: customer.id,
    name: customer.name,
    phone: customer.phone,
    email: customer.email || "",
    exp:
      Date.now() +
      1000 * 60 * 60 * 24 * 30
  };

  const raw = Buffer
    .from(JSON.stringify(payload))
    .toString("base64url");

  const signature =
    crypto
      .createHmac(
        "sha256",
        SESSION_SECRET
      )
      .update(raw)
      .digest("base64url");

  return raw + "." + signature;
}


function readToken(req) {
  const header =
    req.headers.authorization || "";

  if (!header.startsWith("Bearer ")) {
    return null;
  }

  const token = header.slice(7);
  const parts = token.split(".");

  if (parts.length !== 2) {
    return null;
  }

  const raw = parts[0];
  const signature = parts[1];

  const expected =
    crypto
      .createHmac(
        "sha256",
        SESSION_SECRET
      )
      .update(raw)
      .digest("base64url");

  if (
    signature.length !==
    expected.length
  ) {
    return null;
  }

  try {
    if (
      !crypto.timingSafeEqual(
        Buffer.from(signature),
        Buffer.from(expected)
      )
    ) {
      return null;
    }
  } catch {
    return null;
  }

  try {
    const payload =
      JSON.parse(
        Buffer.from(
          raw,
          "base64url"
        ).toString("utf8")
      );

    if (
      !payload.id ||
      !payload.exp ||
      payload.exp < Date.now()
    ) {
      return null;
    }

    return payload;

  } catch {
    return null;
  }
}


/* =========================================================
   REQUIRED LOGIN
========================================================= */

function requireAuth(req, res, next) {
  const customer = readToken(req);

  if (!customer) {
    return res.status(401).json({
      error:
        "Please sign in to continue."
    });
  }

  req.customer = customer;

  next();
}


/* =========================================================
   OPTIONAL LOGIN
   Guest customers are allowed.
========================================================= */

function optionalAuth(req, res, next) {
  req.customer = readToken(req);
  next();
}


/* =========================================================
   GOOGLE SHEETS
========================================================= */

async function sheet(action, data) {
  if (!GOOGLE_SCRIPT_URL) {
    throw new Error(
      "Google Sheets connection is not configured on the backend."
    );
  }

  const response =
    await fetch(
      GOOGLE_SCRIPT_URL,
      {
        method: "POST",

        headers: {
          "Content-Type":
            "text/plain;charset=utf-8"
        },

        body: JSON.stringify({
          action: action,
          ...data
        })
      }
    );

  const text =
    await response.text();

  let result = {};

  try {
    result =
      JSON.parse(text);
  } catch {
    result = {};
  }

  if (
    !response.ok ||
    result.ok === false
  ) {
    throw new Error(
      result.error ||
      "Google Sheets request failed (" +
        response.status +
        ")"
    );
  }

  return result;
}


/* =========================================================
   HEALTH CHECK
========================================================= */

app.get(
  "/health",
  (req, res) => {
    res.json({
      ok: true,
      service: "BS Bites Backend"
    });
  }
);


/* =========================================================
   RAZORPAY CONFIG
========================================================= */

app.get(
  "/api/config",
  (req, res) => {
    res.json({
      keyId: KEY_ID
    });
  }
);


/* =========================================================
   REGISTER
========================================================= */

app.post(
  "/api/auth/register",
  async (req, res) => {

    try {

      const name =
        String(
          req.body.name || ""
        ).trim();

      const phone =
        cleanPhone(
          req.body.phone
        );

      const email =
        normalizeEmail(
          req.body.email
        );

      const password =
        String(
          req.body.password || ""
        );


      if (
        !name ||
        !/^[0-9]{10}$/.test(phone) ||
        password.length < 6
      ) {

        return res.status(400).json({
          error:
            "Please enter your name, a valid 10-digit mobile number and a password of at least 6 characters."
        });
      }


      if (
        email &&
        !/^\S+@\S+\.\S+$/.test(email)
      ) {

        return res.status(400).json({
          error:
            "Please enter a valid email address."
        });
      }


      const existing =
        await sheet(
          "findCustomer",
          {
            identifier:
              phone
          }
        );


      if (existing.customer) {

        return res.status(409).json({
          error:
            "An account with this mobile number already exists. Please sign in."
        });
      }


      if (email) {

        const existingEmail =
          await sheet(
            "findCustomer",
            {
              identifier:
                email
            }
          );


        if (existingEmail.customer) {

          return res.status(409).json({
            error:
              "An account with this email already exists. Please sign in."
          });
        }
      }


      const salt =
        crypto
          .randomBytes(16)
          .toString("hex");


      const passwordHash =
        hashPassword(
          password,
          salt
        );


      const customer = {

        id:
          crypto.randomUUID(),

        name:
          name,

        phone:
          phone,

        email:
          email,

        passwordSalt:
          salt,

        passwordHash:
          passwordHash,

        createdAt:
          new Date().toISOString()
      };


      await sheet(
        "createCustomer",
        {
          customer:
            customer
        }
      );


      const safeCustomer = {

        id:
          customer.id,

        name:
          customer.name,

        phone:
          customer.phone,

        email:
          customer.email
      };


      res.json({

        token:
          makeToken(
            safeCustomer
          ),

        customer:
          safeCustomer

      });


    } catch (error) {

      console.error(
        "REGISTER ERROR:",
        error
      );

      res.status(500).json({
        error:
          error.message ||
          "Could not create account."
      });
    }
  }
);


/* =========================================================
   LOGIN
========================================================= */

app.post(
  "/api/auth/login",
  async (req, res) => {

    try {

      const identifier =
        String(
          req.body.identifier || ""
        ).trim();

      const password =
        String(
          req.body.password || ""
        );


      if (
        !identifier ||
        !password
      ) {

        return res.status(400).json({
          error:
            "Please enter your mobile/email and password."
        });
      }


      const lookup =
        await sheet(
          "findCustomer",
          {
            identifier:
              identifier.includes("@")
                ? normalizeEmail(
                    identifier
                  )
                : cleanPhone(
                    identifier
                  )
          }
        );


      const customer =
        lookup.customer;


      if (!customer) {

        return res.status(401).json({
          error:
            "Account not found. Please check your details or create an account."
        });
      }


      const passwordHash =
        hashPassword(
          password,
          customer.passwordSalt || ""
        );


      if (
        passwordHash !==
        customer.passwordHash
      ) {

        return res.status(401).json({
          error:
            "Incorrect password."
        });
      }


      const safeCustomer = {

        id:
          customer.id,

        name:
          customer.name,

        phone:
          customer.phone,

        email:
          customer.email || ""
      };


      res.json({

        token:
          makeToken(
            safeCustomer
          ),

        customer:
          safeCustomer

      });


    } catch (error) {

      console.error(
        "LOGIN ERROR:",
        error
      );

      res.status(500).json({
        error:
          error.message ||
          "Could not sign in."
      });
    }
  }
);


/* =========================================================
   CURRENT CUSTOMER
========================================================= */

app.get(
  "/api/auth/me",
  requireAuth,
  (req, res) => {

    res.json({
      customer:
        req.customer
    });

  }
);


/* =========================================================
   CUSTOMER ORDERS
========================================================= */

app.get(
  "/api/orders",
  requireAuth,
  async (req, res) => {

    try {

      const result =
        await sheet(
          "getOrders",
          {
            customerId:
              req.customer.id
          }
        );


      res.json({
        orders:
          result.orders || []
      });


    } catch (error) {

      console.error(
        "ORDERS ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Could not load your orders right now."
      });
    }
  }
);


/* =========================================================
   CREATE RAZORPAY ORDER
   LOGIN NOT REQUIRED
========================================================= */

app.post(
  "/api/create-order",
  optionalAuth,
  async (req, res) => {

    try {

      if (!razorpay) {

        return res.status(503).json({
          error:
            "Online payment is not configured yet."
        });
      }


      const cartResult =
        calculateCart(
          req.body.cart
        );


      const customer =
        req.body.customer || {};


      const name =
        String(
          customer.name || ""
        ).trim();


      const phone =
        cleanPhone(
          customer.phone
        );


      const email =
        normalizeEmail(
          customer.email
        );


      const address =
        String(
          customer.address || ""
        ).trim();


      if (
        !name ||
        !/^[0-9]{10}$/.test(phone) ||
        !address
      ) {

        return res.status(400).json({
          error:
            "Please provide a valid name, 10-digit phone number and delivery address."
        });
      }


      const razorpayOrder =
        await razorpay.orders.create({

          amount:
            cartResult.total * 100,

          currency:
            "INR",

          receipt:
            "BSB-" +
            Date.now(),

          notes: {

            customer_name:
              name.slice(
                0,
                255
              ),

            customer_phone:
              phone,

            customer_email:
              email.slice(
                0,
                255
              ),

            products:
              cartResult.normalized
                .map(
                  item =>
                    item.name +
                    " x " +
                    item.qty
                )
                .join(", ")
                .slice(
                  0,
                  255
                )
          }
        });


      res.json({

        orderId:
          razorpayOrder.id,

        amount:
          razorpayOrder.amount,

        currency:
          razorpayOrder.currency

      });


    } catch (error) {

      console.error(
        "CREATE ORDER ERROR:",
        error
      );

      res.status(400).json({
        error:
          error.message ||
          "Could not create payment order."
      });
    }
  }
);


/* =========================================================
   VERIFY RAZORPAY PAYMENT
   LOGIN NOT REQUIRED
========================================================= */

app.post(
  "/api/verify-payment",
  optionalAuth,
  async (req, res) => {

    try {

      if (!razorpay) {

        return res.status(503).json({

          verified:
            false,

          error:
            "Online payment is not configured yet."

        });
      }


      const {
        razorpay_order_id,
        razorpay_payment_id,
        razorpay_signature
      } = req.body;


      if (
        !razorpay_order_id ||
        !razorpay_payment_id ||
        !razorpay_signature
      ) {

        return res.status(400).json({

          verified:
            false,

          error:
            "Missing payment verification data."

        });
      }


      /* -----------------------------------------
         VERIFY SIGNATURE
      ----------------------------------------- */

      const expectedSignature =
        crypto
          .createHmac(
            "sha256",
            KEY_SECRET
          )
          .update(
            razorpay_order_id +
            "|" +
            razorpay_payment_id
          )
          .digest("hex");


      if (
        expectedSignature !==
        razorpay_signature
      ) {

        return res.status(400).json({

          verified:
            false,

          error:
            "Payment signature verification failed."

        });
      }


      /* -----------------------------------------
         GET PAYMENT
      ----------------------------------------- */

      const payment =
        await razorpay.payments.fetch(
          razorpay_payment_id
        );


      if (
        payment.order_id !==
        razorpay_order_id
      ) {

        return res.status(400).json({

          verified:
            false,

          error:
            "Payment does not belong to this order."

        });
      }


      if (
        ![
          "captured",
          "authorized"
        ].includes(
          payment.status
        )
      ) {

        return res.status(400).json({

          verified:
            false,

          error:
            "Payment is not in a valid state."

        });
      }


      /* -----------------------------------------
         CHECK CART
      ----------------------------------------- */

      const cartResult =
        calculateCart(
          req.body.cart
        );


      const expectedAmount =
        cartResult.total * 100;


      if (
        Number(payment.amount) !==
        Number(expectedAmount)
      ) {

        return res.status(400).json({

          verified:
            false,

          error:
            "Payment amount does not match the order total."

        });
      }


      /* -----------------------------------------
         CUSTOMER DETAILS
      ----------------------------------------- */

      const customer =
        req.body.customer || {};


      const name =
        String(
          customer.name || ""
        ).trim();


      const phone =
        cleanPhone(
          customer.phone
        );


      const email =
        normalizeEmail(
          customer.email
        );


      const address =
        String(
          customer.address || ""
        ).trim();


      if (
        !name ||
        !/^[0-9]{10}$/.test(phone) ||
        !address
      ) {

        return res.status(400).json({

          verified:
            false,

          error:
            "Customer name, valid phone number and delivery address are required."

        });
      }


      /* -----------------------------------------
         CUSTOMER ID

         Logged in:
             real customer ID

         Guest:
             GUEST
      ----------------------------------------- */

      const customerId =
        req.customer
          ? req.customer.id
          : "GUEST";


      /* -----------------------------------------
         ORDER DATA
      ----------------------------------------- */

      const orderData = {

        orderId:
          razorpay_order_id,

        customerId:
          customerId,

        name:
          name,

        phone:
          phone,

        email:
          email,

        address:
          address,

        products:
          cartResult.normalized
            .map(
              item =>
                item.name +
                " x " +
                item.qty +
                " = ₹" +
                item.price *
                item.qty
            )
            .join(", "),

        quantity:
          cartResult.normalized
            .reduce(
              (sum, item) =>
                sum + item.qty,
              0
            ),

        total:
          payment.amount / 100,

        paymentStatus:
          "Razorpay - Verified",

        paymentId:
          razorpay_payment_id,

        status:
          "Confirmed",

        date:
          new Date().toISOString()
      };


      /* -----------------------------------------
         SAVE TO GOOGLE SHEETS
      ----------------------------------------- */

      try {

        await sheet(
          "saveOrder",
          {
            order:
              orderData
          }
        );

      } catch (sheetError) {

        console.error(
          "GOOGLE SHEETS SAVE ERROR:",
          sheetError
        );


        return res.status(500).json({

          verified:
            false,

          error:
            "Payment was successful, but the order could not be saved. Please contact BS Bites with payment ID: " +
            razorpay_payment_id

        });
      }


      /* -----------------------------------------
         SUCCESS
      ----------------------------------------- */

      return res.json({

        verified:
          true,

        paymentId:
          razorpay_payment_id,

        orderId:
          razorpay_order_id

      });


    } catch (error) {

      console.error(
        "VERIFY PAYMENT ERROR:",
        error
      );


      return res.status(500).json({

        verified:
          false,

        error:
          error.message ||
          "Could not verify the payment."

      });
    }
  }
);


/* =========================================================
   START SERVER
========================================================= */

app.listen(
  PORT,
  () => {

    console.log(
      "BS Bites running on port " +
      PORT
    );

  }
);
