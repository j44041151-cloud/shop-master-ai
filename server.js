require("dotenv").config();

const express = require("express");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const multer = require("multer");
const { createClient } = require("@supabase/supabase-js");

const app = express();
const PORT = process.env.PORT || 3000;

// ==========================================
// 1. FOLDERS
// ==========================================

const publicDir = path.join(__dirname, "public");
const uploadDir = path.join(__dirname, "uploads");

fs.mkdirSync(uploadDir, { recursive: true });

// ==========================================
// 2. MIDDLEWARE
// ==========================================

app.use(express.json({ limit: "1mb" }));
app.use(express.static(publicDir));

// ==========================================
// 3. SUPABASE CONNECTION
// ==========================================

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SECRET_KEY;

if (!supabaseUrl || !supabaseKey) {
  console.error(
    "Missing SUPABASE_URL or SUPABASE_SECRET_KEY in .env"
  );
  process.exit(1);
}

const supabase = createClient(supabaseUrl, supabaseKey);

// ==========================================
// 4. PHOTO UPLOAD
// ==========================================

const allowedTypes = {
  "image/jpeg": ".jpg",
  "image/png": ".png",
  "image/webp": ".webp"
};

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 5 * 1024 * 1024,
    files: 1
  },
  fileFilter: (req, file, callback) => {
    if (!allowedTypes[file.mimetype]) {
      return callback(
        new Error("Choose a JPG, PNG or WebP photo.")
      );
    }

    callback(null, true);
  }
});

// ==========================================
// 5. DATABASE PRODUCT FORMAT
// ==========================================

function formatProduct(row) {
  const composition = row.composition || {};
  const piecesPerSet = row.size_end - row.size_start + 1;

  return {
    id: row.id,
    designNumber: row.design_number,
    name: row.name,
    category: row.category,
    price: row.price_per_set == null
      ? null
      : Number(row.price_per_set),
    stockSets: Number(row.stock_sets),
    sizeStart: Number(row.size_start),
    sizeEnd: Number(row.size_end),
    composition,
    piecesPerSet,
    totalGarments: Number(row.stock_sets) * piecesPerSet,
    photoUrl: row.photo_url
      ? (row.photo_url.startsWith("/uploads/")
          ? row.photo_url
          : `/api/products/${row.id}/photo`)
      : null,
    createdAt: row.created_at
  };
}

// ==========================================
// 6. HEALTH CHECK
// ==========================================

app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    shop: "Jai Shree Mahakal Garments",
    message: "Shop AI backend is running!"
  });
});

// ==========================================
// 6A. ADMIN LOGIN AND API PROTECTION
// ==========================================
// Set ADMIN_PASSWORD and SESSION_SECRET in the host environment (or local .env).
// Never put these values in public/index.html or commit them to GitHub.
const adminPassword = process.env.ADMIN_PASSWORD;
const sessionSecret = process.env.SESSION_SECRET;
const isProduction = process.env.NODE_ENV === "production";
const cookieName = "shop_ai_session";
const SESSION_MAX_AGE_SECONDS = 60 * 60 * 12; // 12 hours
const loginAttempts = new Map();

if (!adminPassword || !sessionSecret || sessionSecret.length < 32) {
  console.error("Missing ADMIN_PASSWORD or SESSION_SECRET (SESSION_SECRET must be at least 32 characters). Add them to your local .env or hosting environment.");
  process.exit(1);
}

function signSession(expiry) {
  const payload = String(expiry);
  const signature = crypto.createHmac("sha256", sessionSecret).update(payload).digest("hex");
  return `${payload}.${signature}`;
}

function isValidSession(value) {
  if (!value || typeof value !== "string") return false;
  const parts = value.split(".");
  if (parts.length !== 2 || !/^\d+$/.test(parts[0])) return false;
  const expiry = Number(parts[0]);
  if (!Number.isSafeInteger(expiry) || expiry <= Math.floor(Date.now() / 1000)) return false;
  const expected = crypto.createHmac("sha256", sessionSecret).update(parts[0]).digest();
  let supplied;
  try { supplied = Buffer.from(parts[1], "hex"); } catch { return false; }
  return supplied.length === expected.length && crypto.timingSafeEqual(supplied, expected);
}

function readCookie(req, name) {
  const header = req.headers.cookie || "";
  for (const part of header.split(";")) {
    const index = part.indexOf("=");
    if (index < 0) continue;
    if (part.slice(0, index).trim() === name) return decodeURIComponent(part.slice(index + 1).trim());
  }
  return "";
}

function setSessionCookie(res, value, maxAge) {
  const flags = [`${cookieName}=${encodeURIComponent(value)}`, "Path=/", "HttpOnly", "SameSite=Strict", `Max-Age=${maxAge}`];
  if (isProduction) flags.push("Secure");
  res.setHeader("Set-Cookie", flags.join("; "));
}

app.post("/api/login", (req, res) => {
  const ip = req.ip || req.socket.remoteAddress || "unknown";
  const now = Date.now();
  const attempts = loginAttempts.get(ip) || { count: 0, windowStart: now, blockedUntil: 0 };
  if (now < attempts.blockedUntil) {
    return res.status(429).json({ error: "Too many login attempts. Please wait 10 minutes and try again." });
  }
  if (now - attempts.windowStart > 10 * 60 * 1000) {
    attempts.count = 0;
    attempts.windowStart = now;
    attempts.blockedUntil = 0;
  }
  const supplied = String(req.body?.password || "");
  const suppliedHash = crypto.createHash("sha256").update(supplied).digest();
  const expectedHash = crypto.createHash("sha256").update(adminPassword).digest();
  const valid = suppliedHash.length === expectedHash.length && crypto.timingSafeEqual(suppliedHash, expectedHash);
  if (!valid) {
    attempts.count += 1;
    if (attempts.count >= 8) attempts.blockedUntil = now + 10 * 60 * 1000;
    loginAttempts.set(ip, attempts);
    return res.status(401).json({ error: "Password galat hai. Dobara try karo." });
  }
  loginAttempts.delete(ip);
  const expiry = Math.floor(Date.now() / 1000) + SESSION_MAX_AGE_SECONDS;
  setSessionCookie(res, signSession(expiry), SESSION_MAX_AGE_SECONDS);
  res.json({ success: true });
});

app.post("/api/logout", (req, res) => {
  setSessionCookie(res, "", 0);
  res.json({ success: true });
});

function requireLogin(req, res, next) {
  const token = readCookie(req, cookieName);
  if (!isValidSession(token)) return res.status(401).json({ error: "Login required." });
  next();
}

// All shop data APIs and uploaded product photos require a valid signed session.
app.use("/api", (req, res, next) => {
  if (req.path === "/health" || req.path === "/login" || req.path === "/logout") return next();
  return requireLogin(req, res, next);
});


// Legacy local photos are also protected by the login session.
app.use("/uploads", requireLogin, express.static(uploadDir));

// ==========================================
// 7. PRODUCT PHOTOS + GET ALL PRODUCTS
// ==========================================

app.get("/api/products/:id/photo", async (req, res) => {
  try {
    const productId = Number(req.params.id);

    if (!Number.isSafeInteger(productId) || productId < 1) {
      return res.status(400).json({ error: "Invalid product ID." });
    }

    const { data: product, error: productError } = await supabase
      .from("products")
      .select("photo_url")
      .eq("id", productId)
      .single();

    if (productError || !product || !product.photo_url) {
      return res.status(404).json({ error: "Photo not found." });
    }

    // Older products may still reference local photos.
    if (product.photo_url.startsWith("/uploads/")) {
      const filename = path.basename(product.photo_url);
      const filePath = path.join(uploadDir, filename);

      if (!fs.existsSync(filePath)) {
        return res.status(404).json({ error: "Old photo not found." });
      }

      res.setHeader("Cache-Control", "private, no-store");
      return res.sendFile(filePath);
    }

    // Only read object paths managed by this app from the private bucket.
    if (!product.photo_url.startsWith("products/") || product.photo_url.includes("..")) {
      return res.status(404).json({ error: "Photo path is invalid." });
    }

    const { data: photo, error: photoError } = await supabase.storage
      .from("product-images")
      .download(product.photo_url);

    if (photoError || !photo) {
      console.error("Private photo download error:", photoError?.message);
      return res.status(404).json({ error: "Photo not found in storage." });
    }

    const contentType = product.photo_url.endsWith(".png")
      ? "image/png"
      : product.photo_url.endsWith(".webp")
        ? "image/webp"
        : "image/jpeg";

    res.setHeader("Content-Type", contentType);
    res.setHeader("Cache-Control", "private, no-store");
    return res.send(Buffer.from(await photo.arrayBuffer()));
  } catch (error) {
    console.error("Product photo error:", error.message);
    return res.status(500).json({ error: "Unable to load photo." });
  }
});

app.get("/api/products", async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("products")
      .select("*")
      .order("id", { ascending: false });

    if (error) {
      console.error("Supabase read error:", error.message);

      return res.status(500).json({
        message: "Could not load products. Check the products table."
      });
    }

    res.json(data.map(formatProduct));
  } catch (error) {
    console.error("Load products error:", error.message);

    res.status(500).json({
      message: "Unable to load products."
    });
  }
});

// ==========================================
// 8. ADD PRODUCT
// ==========================================

app.post(
  "/api/products",
  upload.single("photo"),
  async (req, res) => {
    let uploadedObjectPath = null;

    try {
      const {
        designNumber,
        name,
        category,
        price,
        stockSets,
        sizeStart,
        sizeEnd
      } = req.body;

      // Basic validation
      if (
        typeof designNumber !== "string" ||
        !designNumber.trim() ||
        typeof name !== "string" ||
        !name.trim() ||
        !["Boys Wear", "Girls Wear"].includes(category)
      ) {
        return res.status(400).json({
          message: "Enter design number, product name and category."
        });
      }

      // Validate size range
      const start = Number(sizeStart);
      const end = Number(sizeEnd);

      if (
        sizeStart === "" ||
        sizeEnd === "" ||
        !Number.isSafeInteger(start) ||
        !Number.isSafeInteger(end) ||
        start < 1 ||
        end < start ||
        end - start > 199
      ) {
        return res.status(400).json({
          message: "Enter a valid size range of at most 200 sizes."
        });
      }

      // Validate complete sets
      const stock = Number(stockSets);

      if (
        stockSets === "" ||
        !Number.isSafeInteger(stock) ||
        stock < 0 ||
        stock > 1000000
      ) {
        return res.status(400).json({
          message: "Stock must be a whole number of complete sets."
        });
      }

      // Validate optional price
      let cleanPrice = null;

      if (price !== "") {
        cleanPrice = Number(price);

        if (
          !Number.isFinite(cleanPrice) ||
          cleanPrice < 0 ||
          cleanPrice > 1000000000
        ) {
          return res.status(400).json({
            message: "Enter a valid price or leave it blank."
          });
        }
      }

      // Every size contains exactly one piece per set.
      const composition = {};

      for (let size = start; size <= end; size++) {
        composition[String(size)] = 1;
      }

      const piecesPerSet = end - start + 1;
      const totalGarments = stock * piecesPerSet;

      if (!Number.isSafeInteger(totalGarments)) {
        return res.status(400).json({
          message: "Total garment quantity is too large."
        });
      }

      // Upload optional photo to the private Supabase Storage bucket.
      if (req.file) {
        const extension = allowedTypes[req.file.mimetype];
        uploadedObjectPath = `products/${crypto.randomUUID()}${extension}`;

        const { error: uploadError } = await supabase.storage
          .from("product-images")
          .upload(uploadedObjectPath, req.file.buffer, {
            contentType: req.file.mimetype,
            upsert: false
          });

        if (uploadError) {
          console.error("Photo storage upload error:", uploadError.message);
          return res.status(500).json({
            message: "Photo upload nahi hui. Supabase Storage settings check karo."
          });
        }
      }

      // Store the private bucket object path, not a public URL.
      const productToInsert = {
        design_number: designNumber.trim(),
        name: name.trim(),
        category,
        price_per_set: cleanPrice,
        stock_sets: stock,
        size_start: start,
        size_end: end,
        composition,
        photo_url: uploadedObjectPath
      };

      const { data, error } = await supabase
        .from("products")
        .insert(productToInsert)
        .select("*")
        .single();

      if (error) {
        console.error("Supabase insert error:", error.message);

        // Remove uploaded photo if the database insert failed.
        if (uploadedObjectPath) {
          const { error: cleanupError } = await supabase.storage
            .from("product-images")
            .remove([uploadedObjectPath]);
          if (cleanupError) {
            console.error("Photo cleanup error:", cleanupError.message);
          }
        }

        if (error.code === "23505") {
          return res.status(409).json({
            message: "This design number already exists."
          });
        }

        return res.status(500).json({
          message:
            "Database could not save the product. Check table columns and permissions."
        });
      }

      return res.status(201).json({
        message: "Design and stock saved successfully!",
        product: formatProduct(data)
      });
    } catch (error) {
      console.error("Product creation error:", error.message);

      if (uploadedObjectPath) {
        const { error: cleanupError } = await supabase.storage
          .from("product-images")
          .remove([uploadedObjectPath]);
        if (cleanupError) {
          console.error("Photo cleanup error:", cleanupError.message);
        }
      }

      return res.status(500).json({
        message: "Unable to save the product."
      });
    }
  }
);

// ==========================================
// 9. UPLOAD ERROR HANDLER
// ==========================================

app.use((error, req, res, next) => {
  if (res.headersSent) {
    return next(error);
  }

  if (error instanceof multer.MulterError) {
    const message = error.code === "LIMIT_FILE_SIZE"
      ? "Photo must be 5 MB or smaller."
      : "Photo upload failed. Please try again.";

    return res.status(400).json({ message });
  }

  if (error) {
    return res.status(400).json({
      message: error.message || "Unexpected error."
    });
  }

  next();
});

// ==========================================
// 10. START SERVER
// ==========================================

/* PARTY MANAGEMENT API */

// Get all parties
app.get("/api/parties", async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("parties")
      .select("*")
      .order("id", { ascending: false });

    if (error) throw error;

    res.json(data);
  } catch (error) {
    console.error("Fetch parties error:", error.message);
    res.status(500).json({ error: "Parties load nahi hui." });
  }
});

// Add a new party
app.post("/api/parties", async (req, res) => {
  try {
    const { name, phone, address, opening_balance } = req.body;

    if (!name || !name.trim()) {
      return res.status(400).json({
        error: "Party ka naam zaroori hai."
      });
    }

    const balance = Number(opening_balance ?? 0);

    if (!Number.isFinite(balance)) {
      return res.status(400).json({
        error: "Opening balance sahi number hona chahiye."
      });
    }

    const { data, error } = await supabase
      .from("parties")
      .insert([{
        name: name.trim(),
        phone: phone?.trim() || null,
        address: address?.trim() || null,
        opening_balance: balance
      }])
      .select()
      .single();

    if (error) throw error;

    res.status(201).json(data);
  } catch (error) {
    console.error("Add party error:", error.message);
    res.status(500).json({
      error: "Party save nahi hui. Server terminal check karo."
    });
  }
});



/* NEW DESIGN FROM ORDER BOOKING: create zero-stock catalogue entry */
app.post("/api/order-designs", async (req, res) => {
  try {
    const { designNumber, name, category, sizeStart, sizeEnd } = req.body || {};
    const start = Number(sizeStart);
    const end = Number(sizeEnd);
    if (typeof designNumber !== "string" || !designNumber.trim() ||
        typeof name !== "string" || !name.trim() ||
        !["Boys Wear", "Girls Wear"].includes(category) ||
        !Number.isSafeInteger(start) || !Number.isSafeInteger(end) ||
        start < 1 || end < start || end - start > 199) {
      return res.status(400).json({ error: "New design details ya size range invalid hai." });
    }
    const composition = {};
    for (let size = start; size <= end; size++) composition[String(size)] = 1;
    const { data, error } = await supabase.from("products").insert({
      design_number: designNumber.trim(), name: name.trim(), category,
      size_start: start, size_end: end, composition,
      stock_sets: 0, price_per_set: null, photo_url: null
    }).select("id,design_number,name,category,stock_sets").single();
    if (error) {
      if (error.code === "23505") return res.status(409).json({
        error: "Ye design number pehle se hai. Existing design select karo."
      });
      throw error;
    }
    res.status(201).json(data);
  } catch (error) {
    console.error("Order new design error:", error.message);
    res.status(500).json({ error: "New design save nahi hua. Server terminal check karo." });
  }
});

/* ORDER BOOKING API */

app.get("/api/orders", async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("orders")
      .select(`
        id, party_id, order_date, status, total_amount, notes,
        parties(name, phone),
        order_items(
          id, order_id, product_id, sets, rate_per_set, line_total,
          products(design_number, name, category, stock_sets)
        )
      `)
      .order("id", { ascending: false });

    if (error) throw error;

    const itemIds = (data || []).flatMap(order => (order.order_items || []).map(item => item.id));
    let dispatchRows = [];
    let cancellationRows = [];
    if (itemIds.length) {
      const [{ data: dispatched, error: dispatchError }, { data: cancelled, error: cancellationError }] = await Promise.all([
        supabase.from("dispatches").select("order_item_id,sets_dispatched").in("order_item_id", itemIds),
        supabase.from("order_cancellations").select("order_item_id,sets_cancelled,cancelled_dispatched_sets,returned_to_stock").in("order_item_id", itemIds)
      ]);
      if (dispatchError) throw dispatchError;
      if (cancellationError) throw cancellationError;
      dispatchRows = dispatched || [];
      cancellationRows = cancelled || [];
    }

    const dispatchedByItem = new Map();
    for (const row of dispatchRows) {
      const key = String(row.order_item_id);
      dispatchedByItem.set(key, (dispatchedByItem.get(key) || 0) + Number(row.sets_dispatched || 0));
    }
    const cancelledByItem = new Map();
    const cancelledDispatchedByItem = new Map();
    const returnedStockByItem = new Map();
    for (const row of cancellationRows) {
      if (row.order_item_id == null) continue;
      const key = String(row.order_item_id);
      cancelledByItem.set(key, (cancelledByItem.get(key) || 0) + Number(row.sets_cancelled || 0));
      cancelledDispatchedByItem.set(key, (cancelledDispatchedByItem.get(key) || 0) + Number(row.cancelled_dispatched_sets || 0));
      if (row.returned_to_stock) returnedStockByItem.set(key, (returnedStockByItem.get(key) || 0) + Number(row.cancelled_dispatched_sets || 0));
    }

    const enriched = (data || []).map(order => ({
      ...order,
      order_items: (order.order_items || []).map(item => {
        const key = String(item.id);
        const dispatchedSets = dispatchedByItem.get(key) || 0;
        const cancelledSets = cancelledByItem.get(key) || 0;
        const cancelledDispatchedSets = cancelledDispatchedByItem.get(key) || 0;
        const pendingCancelledSets = Math.max(0, cancelledSets - cancelledDispatchedSets);
        return {
          ...item,
          dispatchedSets,
          cancelledSets,
          cancelledDispatchedSets,
          returnedStockSets: returnedStockByItem.get(key) || 0,
          pendingSets: Math.max(0, Number(item.sets || 0) - dispatchedSets - pendingCancelledSets)
        };
      })
    }));
    res.json(enriched);
  } catch (error) {
    console.error("Load orders error:", error.message);
    res.status(500).json({ error: "Orders load nahi hue." });
  }
});

app.post("/api/orders", async (req, res) => {
  try {
    const { partyId, items, notes } = req.body;

    if (!partyId || !Array.isArray(items) || items.length === 0) {
      return res.status(400).json({
        error: "Party aur kam se kam ek design select karo."
      });
    }

    const { data, error } = await supabase.rpc("create_shop_order", {
      p_party_id: Number(partyId),
      p_items: items.map(item => ({
        product_id: Number(item.productId),
        sets: Number(item.sets),
        rate_per_set: Number(item.ratePerSet)
      })),
      p_notes: notes || null
    });

    if (error) throw error;

    // Automatically create only the additional factory quantity needed
    // across all outstanding customer orders for each product.
    const orderId = Number(data?.order_id ?? data?.id);
    const createdFactoryRequirements = [];
    const factoryWarnings = [];

    if (Number.isSafeInteger(orderId) && orderId > 0) {
      try {
        const [
          { data: allOrders, error: ordersError },
          { data: allItems, error: itemsError },
          { data: dispatchRows, error: dispatchError },
          { data: cancellationRows, error: cancellationError },
          { data: products, error: productsError },
          { data: factoryRows, error: factoryError },
          { data: newItems, error: newItemsError }
        ] = await Promise.all([
          supabase.from("orders").select("id,status").neq("status", "cancelled"),
          supabase.from("order_items").select("id,order_id,product_id,sets"),
          supabase.from("dispatches").select("order_item_id,sets_dispatched"),
          supabase.from("order_cancellations").select("order_item_id,sets_cancelled"),
          supabase.from("products").select("id,stock_sets"),
          supabase.from("factory_orders").select("product_id,sets_ordered,sets_received"),
          supabase.from("order_items").select("id,order_id,product_id,sets").eq("order_id", orderId)
        ]);

        for (const err of [ordersError, itemsError, dispatchError, cancellationError, productsError, factoryError, newItemsError]) {
          if (err) throw err;
        }

        const eligibleOrderIds = new Set((allOrders || [])
          .filter(order => !["cancelled", "dispatched"].includes(String(order.status || "").toLowerCase()))
          .map(order => String(order.id)));
        const dispatchedByItem = new Map();
        for (const row of dispatchRows || []) {
          const key = String(row.order_item_id);
          dispatchedByItem.set(key, (dispatchedByItem.get(key) || 0) + Number(row.sets_dispatched || 0));
        }
        const cancelledByItem = new Map();
        for (const row of cancellationRows || []) {
          if (row.order_item_id == null) continue;
          const key = String(row.order_item_id);
          cancelledByItem.set(key, (cancelledByItem.get(key) || 0) + Number(row.sets_cancelled || 0));
        }

        const outstandingByProduct = new Map();
        for (const item of allItems || []) {
          if (!eligibleOrderIds.has(String(item.order_id))) continue;
          const outstanding = Math.max(
            0,
            Number(item.sets || 0) -
              (dispatchedByItem.get(String(item.id)) || 0) -
              (cancelledByItem.get(String(item.id)) || 0)
          );
          const key = String(item.product_id);
          outstandingByProduct.set(key, (outstandingByProduct.get(key) || 0) + outstanding);
        }

        const productById = new Map((products || []).map(product => [String(product.id), product]));
        const factoryPendingByProduct = new Map();
        for (const row of factoryRows || []) {
          const key = String(row.product_id);
          const pending = Math.max(0, Number(row.sets_ordered || 0) - Number(row.sets_received || 0));
          factoryPendingByProduct.set(key, (factoryPendingByProduct.get(key) || 0) + pending);
        }

        // The newest order item is used as the reference for any newly discovered
        // shortage. Demand is aggregated by product to avoid duplicate factory orders.
        const newestItemByProduct = new Map((newItems || []).map(item => [String(item.product_id), item]));
        for (const [productKey, totalOutstanding] of outstandingByProduct.entries()) {
          const product = productById.get(productKey);
          const newestItem = newestItemByProduct.get(productKey);
          if (!product || !newestItem) continue;

          const availableStock = Number(product.stock_sets || 0);
          const alreadyOnOrder = factoryPendingByProduct.get(productKey) || 0;
          const requiredNow = Math.max(0, totalOutstanding - availableStock - alreadyOnOrder);
          if (requiredNow < 1) continue;

          const { data: factoryRecord, error: factoryInsertError } = await supabase
            .from("factory_orders")
            .insert({
              product_id: Number(productKey),
              order_id: orderId,
              order_item_id: newestItem.id,
              sets_ordered: requiredNow,
              sets_received: 0,
              notes: "Auto-generated from customer order booking"
            })
            .select("id,product_id,order_id,order_item_id,sets_ordered,sets_received")
            .single();

          if (factoryInsertError) {
            factoryWarnings.push(`Design product ID ${productKey}: ${factoryInsertError.message}`);
            continue;
          }
          createdFactoryRequirements.push({
            id: factoryRecord.id,
            productId: factoryRecord.product_id,
            orderId: factoryRecord.order_id,
            orderItemId: factoryRecord.order_item_id,
            setsOrdered: Number(factoryRecord.sets_ordered)
          });
        }
      } catch (factoryError) {
        console.error("Auto factory requirement error:", factoryError.message);
        factoryWarnings.push("Order save ho gaya, lekin factory requirement auto-create nahi ho paayi. Factory Dashboard check karo.");
      }
    }

    res.status(201).json({
      ...(data && typeof data === "object" ? data : { result: data }),
      factoryRequirementsCreated: createdFactoryRequirements,
      factoryWarnings
    });
  } catch (error) {
    console.error("Create order error:", error.message);
    res.status(500).json({
      error: error.message || "Order save nahi hua."
    });
  }
});


/* DISPATCH API: deduct shop stock only when goods are actually dispatched. */
app.post("/api/order-items/:id/dispatch", async (req, res) => {
  try {
    const orderItemId = Number(req.params.id);
    const sets = Number(req.body.sets);
    const notes = typeof req.body.notes === "string" ? req.body.notes.trim() : "";

    if (!Number.isSafeInteger(orderItemId) || orderItemId < 1 || !Number.isSafeInteger(sets) || sets < 1) {
      return res.status(400).json({ error: "Order item aur dispatch quantity valid whole numbers hone chahiye." });
    }

    const { data, error } = await supabase.rpc("dispatch_order_item", {
      p_order_item_id: orderItemId,
      p_sets: sets,
      p_notes: notes || null
    });
    if (error) throw error;

    // Mark the order dispatched only when every item has no remaining quantity.
    const { data: item, error: itemError } = await supabase
      .from("order_items").select("id,order_id,sets").eq("id", orderItemId).single();
    if (itemError) throw itemError;

    const { data: orderItems, error: orderItemsError } = await supabase
      .from("order_items").select("id,sets").eq("order_id", item.order_id);
    if (orderItemsError) throw orderItemsError;

    const ids = (orderItems || []).map(row => row.id);
    const [{ data: allDispatches, error: allDispatchesError }, { data: allCancellations, error: allCancellationsError }] = await Promise.all([
      supabase.from("dispatches").select("order_item_id,sets_dispatched").in("order_item_id", ids),
      supabase.from("order_cancellations").select("order_item_id,sets_cancelled,cancelled_dispatched_sets").in("order_item_id", ids)
    ]);
    if (allDispatchesError) throw allDispatchesError;
    if (allCancellationsError) throw allCancellationsError;

    const remaining = (orderItems || []).reduce((sum, row) => {
      const dispatched = (allDispatches || []).filter(d => String(d.order_item_id) === String(row.id)).reduce((n, d) => n + Number(d.sets_dispatched || 0), 0);
      const cancelled = (allCancellations || []).filter(c => String(c.order_item_id) === String(row.id)).reduce((n, c) => n + Number(c.sets_cancelled || 0), 0);
      return sum + Math.max(0, Number(row.sets || 0) - dispatched - cancelled);
    }, 0);

    if (remaining === 0) {
      const { error: statusError } = await supabase.from("orders").update({ status: "dispatched" }).eq("id", item.order_id);
      if (statusError) console.error("Order status update warning:", statusError.message);
    }

    res.json({ success: true, result: data, orderId: item.order_id, remainingSets: remaining });
  } catch (error) {
    console.error("Dispatch order item error:", error.message);
    res.status(400).json({ error: error.message || "Dispatch save nahi hua." });
  }
});

/* Cancellation history for audit and customer follow-up. */
app.get("/api/order-cancellations", async (req, res) => {
  try {
    const { data: cancellations, error } = await supabase
      .from("order_cancellations")
      .select("id,order_id,order_item_id,sets_cancelled,cancelled_dispatched_sets,returned_to_stock,reason,cancelled_at,notes")
      .order("cancelled_at", { ascending: false });
    if (error) throw error;
    const orderIds = [...new Set((cancellations || []).map(row => row.order_id).filter(Boolean))];
    const itemIds = [...new Set((cancellations || []).map(row => row.order_item_id).filter(Boolean))];
    const [{ data: orders, error: ordersError }, { data: items, error: itemsError }] = await Promise.all([
      orderIds.length ? supabase.from("orders").select("id,party_id,parties(name)").in("id", orderIds) : Promise.resolve({ data: [], error: null }),
      itemIds.length ? supabase.from("order_items").select("id,product_id,products(design_number,name)").in("id", itemIds) : Promise.resolve({ data: [], error: null })
    ]);
    if (ordersError) throw ordersError;
    if (itemsError) throw itemsError;
    const orderMap = new Map((orders || []).map(row => [String(row.id), row]));
    const itemMap = new Map((items || []).map(row => [String(row.id), row]));
    res.json((cancellations || []).map(row => ({
      ...row,
      partyName: orderMap.get(String(row.order_id))?.parties?.name || `Order #${row.order_id}`,
      designNumber: itemMap.get(String(row.order_item_id))?.products?.design_number || "—",
      productName: itemMap.get(String(row.order_item_id))?.products?.name || ""
    })));
  } catch (error) {
    console.error("Cancellation history error:", error.message);
    res.status(500).json({ error: "Cancellation history load nahi hui." });
  }
});

/* ORDER CANCELLATION API: only undispatched sets can be cancelled. */
app.post("/api/order-items/:id/cancel", async (req, res) => {
  try {
    const orderItemId = Number(req.params.id);
    const sets = Number(req.body.sets);
    const reason = typeof req.body.reason === "string" ? req.body.reason.trim() : "";
    const notes = typeof req.body.notes === "string" ? req.body.notes.trim() : "";

    if (!Number.isSafeInteger(orderItemId) || orderItemId < 1 || !Number.isSafeInteger(sets) || sets < 1) {
      return res.status(400).json({ error: "Order item aur cancellation quantity valid whole numbers hone chahiye." });
    }
    if (!reason) {
      return res.status(400).json({ error: "Cancellation ka reason likhna zaroori hai." });
    }

    const { data: item, error: itemError } = await supabase
      .from("order_items").select("id,order_id,sets,rate_per_set").eq("id", orderItemId).single();
    if (itemError) throw itemError;

    const [{ data: dispatchRows, error: dispatchError }, { data: cancellationRows, error: cancellationError }] = await Promise.all([
      supabase.from("dispatches").select("sets_dispatched").eq("order_item_id", orderItemId),
      supabase.from("order_cancellations").select("sets_cancelled,cancelled_dispatched_sets").eq("order_item_id", orderItemId)
    ]);
    if (dispatchError) throw dispatchError;
    if (cancellationError) throw cancellationError;

    const dispatched = (dispatchRows || []).reduce((sum, row) => sum + Number(row.sets_dispatched || 0), 0);
    const cancelled = (cancellationRows || []).reduce((sum, row) => sum + Math.max(0, Number(row.sets_cancelled || 0) - Number(row.cancelled_dispatched_sets || 0)), 0);
    const pending = Math.max(0, Number(item.sets || 0) - dispatched - cancelled);
    if (sets > pending) {
      return res.status(400).json({ error: `Sirf ${pending} pending sets cancel ho sakte hain.` });
    }

    const { error: insertError } = await supabase.from("order_cancellations").insert({
      order_id: item.order_id,
      order_item_id: item.id,
      sets_cancelled: sets,
      reason,
      notes: notes || null
    });
    if (insertError) throw insertError;

    // Reduce the order's billed total for cancelled sets, using that line's saved rate.
    const cancelledValue = sets * Number(item.rate_per_set || 0);
    const { data: orderRecord, error: orderReadError } = await supabase
      .from("orders").select("id,total_amount").eq("id", item.order_id).single();
    if (orderReadError) throw orderReadError;
    const adjustedTotal = Math.max(0, Number(orderRecord.total_amount || 0) - cancelledValue);
    const { error: totalUpdateError } = await supabase
      .from("orders").update({ total_amount: adjustedTotal }).eq("id", item.order_id);
    if (totalUpdateError) throw totalUpdateError;

    const newPending = pending - sets;
    const { data: orderItems, error: orderItemsError } = await supabase
      .from("order_items").select("id,sets").eq("order_id", item.order_id);
    if (orderItemsError) throw orderItemsError;
    const ids = (orderItems || []).map(row => row.id);
    const [{ data: allDispatches, error: allDispatchError }, { data: allCancellations, error: allCancelError }] = await Promise.all([
      supabase.from("dispatches").select("order_item_id,sets_dispatched").in("order_item_id", ids),
      supabase.from("order_cancellations").select("order_item_id,sets_cancelled").in("order_item_id", ids)
    ]);
    if (allDispatchError) throw allDispatchError;
    if (allCancelError) throw allCancelError;

    let remaining = 0;
    let totalDispatched = 0;
    for (const orderRow of orderItems || []) {
      const d = (allDispatches || []).filter(row => String(row.order_item_id) === String(orderRow.id)).reduce((sum, row) => sum + Number(row.sets_dispatched || 0), 0);
      const c = (allCancellations || []).filter(row => String(row.order_item_id) === String(orderRow.id)).reduce((sum, row) => sum + Math.max(0, Number(row.sets_cancelled || 0) - Number(row.cancelled_dispatched_sets || 0)), 0);
      totalDispatched += d;
      remaining += Math.max(0, Number(orderRow.sets || 0) - d - c);
    }
    if (remaining === 0) {
      const newStatus = totalDispatched > 0 ? "dispatched" : "cancelled";
      const { error: statusError } = await supabase.from("orders").update({ status: newStatus }).eq("id", item.order_id);
      if (statusError) console.error("Order status update warning:", statusError.message);
    } else {
      const { error: statusError } = await supabase.from("orders").update({ status: "open" }).eq("id", item.order_id);
      if (statusError) console.error("Order status update warning:", statusError.message);
    }

    res.json({ success: true, orderId: item.order_id, cancelledNow: sets, itemPendingSets: newPending, orderRemainingSets: remaining });
  } catch (error) {
    console.error("Cancel order item error:", error.message);
    res.status(400).json({ error: error.message || "Cancellation save nahi hui." });
  }
});

/* CANCEL ALREADY-DISPATCHED SETS; OPTIONALLY RETURN THEM TO SHOP STOCK. */
app.post("/api/order-items/:id/cancel-dispatched", async (req, res) => {
  try {
    const orderItemId = Number(req.params.id);
    const sets = Number(req.body.sets);
    const reason = typeof req.body.reason === "string" ? req.body.reason.trim() : "";
    const notes = typeof req.body.notes === "string" ? req.body.notes.trim() : "";
    const returnedToStock = req.body.returnedToStock === true;
    if (!Number.isSafeInteger(orderItemId) || orderItemId < 1 || !Number.isSafeInteger(sets) || sets < 1) {
      return res.status(400).json({ error: "Order item aur cancellation quantity valid whole numbers hone chahiye." });
    }
    if (!reason) return res.status(400).json({ error: "Cancellation ka reason likhna zaroori hai." });
    const { data, error } = await supabase.rpc("cancel_dispatched_order_item", {
      p_order_item_id: orderItemId,
      p_sets: sets,
      p_reason: reason,
      p_returned_to_stock: returnedToStock,
      p_notes: notes || null
    });
    if (error) throw error;
    res.json(data);
  } catch (error) {
    console.error("Cancel dispatched sets error:", error.message);
    res.status(400).json({ error: error.message || "Dispatched cancellation save nahi hui." });
  }
});

/* FACTORY ORDER + INVENTORY API */

// Factory orders and current receiving status, separated by Boys/Girls via product category.
app.get("/api/factory-orders", async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("factory_orders")
      .select(`
        id, product_id, order_id, order_item_id,
        sets_ordered, sets_received, notes, ordered_at, updated_at,
        products(id, design_number, name, category, stock_sets),
        orders(id, status, order_date),
        order_items(sets)
      `)
      .order("id", { ascending: false });

    if (error) throw error;

    res.json((data || []).map(row => ({
      ...row,
      sets_pending: Number(row.sets_ordered) - Number(row.sets_received),
      product: row.products,
      order: row.orders,
      order_item: row.order_items
    })));
  } catch (error) {
    console.error("Load factory orders error:", error.message);
    res.status(500).json({
      error: "Factory orders load nahi hue. SQL migration run hui hai ya nahi check karo."
    });
  }
});

// Create a factory order. Quantity is editable by the user in the UI.
app.post("/api/factory-orders", async (req, res) => {
  try {
    const { productId, orderId = null, orderItemId = null, setsOrdered, notes = null } = req.body;
    const product = Number(productId);
    const quantity = Number(setsOrdered);
    const linkedOrder = orderId == null || orderId === "" ? null : Number(orderId);
    const linkedItem = orderItemId == null || orderItemId === "" ? null : Number(orderItemId);

    if (!Number.isSafeInteger(product) || product < 1 ||
        !Number.isSafeInteger(quantity) || quantity < 1) {
      return res.status(400).json({
        error: "Product aur factory quantity valid whole numbers hone chahiye."
      });
    }
    if (linkedOrder !== null && (!Number.isSafeInteger(linkedOrder) || linkedOrder < 1)) {
      return res.status(400).json({ error: "Order ID valid nahi hai." });
    }
    if (linkedItem !== null && (!Number.isSafeInteger(linkedItem) || linkedItem < 1)) {
      return res.status(400).json({ error: "Order item ID valid nahi hai." });
    }

    const { data, error } = await supabase
      .from("factory_orders")
      .insert({
        product_id: product,
        order_id: linkedOrder,
        order_item_id: linkedItem,
        sets_ordered: quantity,
        sets_received: 0,
        notes: typeof notes === "string" && notes.trim() ? notes.trim() : null
      })
      .select(`
        id, product_id, order_id, order_item_id, sets_ordered,
        sets_received, notes, ordered_at, updated_at,
        products(id, design_number, name, category, stock_sets)
      `)
      .single();

    if (error) throw error;

    res.status(201).json({
      ...data,
      sets_pending: Number(data.sets_ordered) - Number(data.sets_received),
      product: data.products
    });
  } catch (error) {
    console.error("Create factory order error:", error.message);
    res.status(500).json({
      error: error.message || "Factory order save nahi hua."
    });
  }
});

// Receive a partial or complete batch. Database RPC updates factory order + stock atomically.
app.post("/api/factory-orders/:id/receive", async (req, res) => {
  try {
    const factoryOrderId = Number(req.params.id);
    const quantity = Number(req.body.setsReceived);
    const notes = typeof req.body.notes === "string" ? req.body.notes.trim() : "";

    if (!Number.isSafeInteger(factoryOrderId) || factoryOrderId < 1 ||
        !Number.isSafeInteger(quantity) || quantity < 1) {
      return res.status(400).json({
        error: "Factory order ID aur receive quantity valid whole numbers hone chahiye."
      });
    }

    const { data, error } = await supabase.rpc("receive_factory_order", {
      p_factory_order_id: factoryOrderId,
      p_sets_received_now: quantity,
      p_notes: notes || null
    });

    if (error) throw error;
    res.json(data);
  } catch (error) {
    console.error("Receive factory stock error:", error.message);
    res.status(400).json({
      error: error.message || "Factory stock receive nahi hua."
    });
  }
});

// Inventory summary for Boys Wear and Girls Wear, including factory quantities.
app.get("/api/inventory/summary", async (req, res) => {
  try {
    const [{ data: products, error: productError }, { data: factoryOrders, error: factoryError }] =
      await Promise.all([
        supabase.from("products")
          .select("id, design_number, name, category, stock_sets")
          .order("design_number", { ascending: true }),
        supabase.from("factory_orders")
          .select("product_id, sets_ordered, sets_received")
      ]);

    if (productError) throw productError;
    if (factoryError) throw factoryError;

    const factoryByProduct = new Map();
    for (const row of factoryOrders || []) {
      const key = String(row.product_id);
      const current = factoryByProduct.get(key) || { setsOrdered: 0, setsReceived: 0, setsPending: 0 };
      current.setsOrdered += Number(row.sets_ordered);
      current.setsReceived += Number(row.sets_received);
      current.setsPending += Number(row.sets_ordered) - Number(row.sets_received);
      factoryByProduct.set(key, current);
    }

    const items = (products || []).map(product => {
      const factory = factoryByProduct.get(String(product.id)) || {
        setsOrdered: 0, setsReceived: 0, setsPending: 0
      };
      return {
        ...product,
        stockSets: Number(product.stock_sets),
        factoryOrderedSets: factory.setsOrdered,
        factoryReceivedSets: factory.setsReceived,
        factoryPendingSets: factory.setsPending
      };
    });

    res.json({
      boysWear: items.filter(item => item.category === "Boys Wear"),
      girlsWear: items.filter(item => item.category === "Girls Wear")
    });
  } catch (error) {
    console.error("Inventory summary error:", error.message);
    res.status(500).json({
      error: "Inventory summary load nahi hua. Factory table aur SQL function check karo."
    });
  }
});



/* PARTY PAYMENTS + LEDGER API */
app.get("/api/payments", async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("payments")
      .select("id, party_id, amount, payment_date, payment_mode, reference, notes, parties(name, phone)")
      .order("payment_date", { ascending: false })
      .order("id", { ascending: false });
    if (error) throw error;
    res.json(data || []);
  } catch (error) {
    console.error("Load payments error:", error.message);
    res.status(500).json({ error: "Payments load nahi hue. Payments table ke columns check karo." });
  }
});

app.post("/api/payments", async (req, res) => {
  try {
    const { partyId, amount, paymentDate, paymentMode, reference, notes } = req.body || {};
    const party = Number(partyId);
    const value = Number(amount);
    if (!Number.isSafeInteger(party) || party < 1 || !Number.isFinite(value) || value <= 0) {
      return res.status(400).json({ error: "Party select karo aur payment amount zero se zyada enter karo." });
    }
    const modes = ["Cash", "UPI", "Bank Transfer", "Cheque", "Other"];
    const mode = modes.includes(paymentMode) ? paymentMode : "Cash";
    const date = paymentDate || new Date().toISOString().slice(0, 10);
    const { data, error } = await supabase.from("payments").insert({
      party_id: party,
      amount: value,
      payment_date: date,
      payment_mode: mode,
      reference: typeof reference === "string" && reference.trim() ? reference.trim() : null,
      notes: typeof notes === "string" && notes.trim() ? notes.trim() : null
    }).select("id, party_id, amount, payment_date, payment_mode, reference, notes").single();
    if (error) throw error;
    res.status(201).json({ success: true, payment: data });
  } catch (error) {
    console.error("Save payment error:", error.message);
    res.status(500).json({ error: error.message || "Payment save nahi hui." });
  }
});

app.get("/api/party-ledger", async (req, res) => {
  try {
    const [{ data: parties, error: partiesError }, { data: orders, error: ordersError }, { data: payments, error: paymentsError }] = await Promise.all([
      supabase.from("parties").select("id, name, phone, opening_balance").order("name", { ascending: true }),
      supabase.from("orders").select("id, party_id, total_amount, status, order_date"),
      supabase.from("payments").select("id, party_id, amount, payment_date, payment_mode, reference, notes")
    ]);
    if (partiesError) throw partiesError;
    if (ordersError) throw ordersError;
    if (paymentsError) throw paymentsError;
    const ledger = (parties || []).map(party => {
      const partyOrders = (orders || []).filter(row => String(row.party_id) === String(party.id));
      const partyPayments = (payments || []).filter(row => String(row.party_id) === String(party.id));
      const orderTotal = partyOrders.filter(row => row.status !== "cancelled").reduce((sum, row) => sum + Number(row.total_amount || 0), 0);
      const paidTotal = partyPayments.reduce((sum, row) => sum + Number(row.amount || 0), 0);
      const opening = Number(party.opening_balance || 0);
      return { ...party, openingBalance: opening, ordersTotal: orderTotal, paymentsTotal: paidTotal, balance: opening + orderTotal - paidTotal, orderCount: partyOrders.length };
    });
    res.json({ ledger, payments: (payments || []).map(payment => ({ ...payment, party: (parties || []).find(p => String(p.id) === String(payment.party_id)) || null })).sort((a,b) => String(b.payment_date).localeCompare(String(a.payment_date)) || Number(b.id)-Number(a.id)) });
  } catch (error) {
    console.error("Party ledger error:", error.message);
    res.status(500).json({ error: "Party ledger load nahi hua. Database tables check karo." });
  }
});

const server = app.listen(PORT, "0.0.0.0", () => {
  console.log("-----------------------------------");
  console.log("Shop AI Backend Started");
  console.log("Shop: Jai Shree Mahakal Garments");
  console.log(`Website: http://localhost:${PORT}`);
  console.log(`API: http://localhost:${PORT}/api/products`);
  console.log("-----------------------------------");
});

server.on("error", (error) => {
  console.error("SERVER LISTEN ERROR:", error);
});


