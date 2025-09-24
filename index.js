const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const SSLCommerzPayment = require("sslcommerz-lts");
const admin = require("firebase-admin");

const express = require("express");
const http = require("http");
const cors = require("cors");
const multer = require("multer");
const path = require("path");
const axios = require("axios");
const FormData = require("form-data");
require("dotenv").config();

// Validate required environment variables
const requiredEnvVars = [
  "MONGODB_URI",
  "FIREBASE_PROJECT_ID",
  "IMAGEBB_API_KEY",
  "EMAIL_USER",
  "EMAIL_PASS",
];

const missingEnvVars = requiredEnvVars.filter((envVar) => !process.env[envVar]);

if (missingEnvVars.length > 0) {
  console.error("❌ Missing required environment variables:");
  missingEnvVars.forEach((envVar) => {
    console.error(`   - ${envVar}`);
  });
  console.error("\nPlease create a .env file with all required variables.");
  console.error("See env.example for reference.");
  process.exit(1);
}

console.log("✅ All required environment variables are set");
const nodemailer = require("nodemailer");

// Initialize Firebase Admin SDK
// For production, you should use a service account key file
// For now, we'll use the project ID and initialize with default credentials
try {
  admin.initializeApp({
    credential: admin.credential.applicationDefault(),
    projectId: process.env.FIREBASE_PROJECT_ID, // Your Firebase project ID
  });
  console.log("Firebase Admin SDK initialized successfully");
} catch (error) {
  console.error("Error initializing Firebase Admin SDK:", error);
  console.log(
    "Firebase Admin SDK not available - user deletion will only affect database"
  );
}

const app = express();

const server = http.createServer(app);

// middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true })); // For form data parsing
app.use(express.static("public"));
app.use(
  cors({
    origin: [
      "http://localhost:5173",
      "https://subidha-home-services.vercel.app",
    ],
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    credentials: true,
    allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With"],
  })
);

// Multer configuration for file uploads (memory storage for ImageBB upload)
const upload = multer({
  storage: multer.memoryStorage(), // Store files in memory for ImageBB upload
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB limit
  },
  fileFilter: function (req, file, cb) {
    // Accept only image files
    if (file.mimetype.startsWith("image/")) {
      cb(null, true);
    } else {
      cb(new Error("Only image files are allowed!"), false);
    }
  },
});

// Serve static files from uploads directory
app.use("/uploads", express.static("uploads"));

// ImageBB API Key (you need to get this from https://api.imgbb.com/)
const IMAGEBB_API_KEY = process.env.IMAGEBB_API_KEY;

// Check if ImageBB API key is valid
const isImageBBEnabled = true;

// Function to upload image to ImageBB
async function uploadToImageBB(imageBuffer, filename) {
  try {
    const formData = new FormData();
    formData.append("image", imageBuffer, {
      filename: filename,
      contentType: "image/jpeg",
    });
    formData.append("key", IMAGEBB_API_KEY);

    const response = await axios.post(
      "https://api.imgbb.com/1/upload",
      formData,
      {
        headers: {
          ...formData.getHeaders(),
        },
      }
    );

    if (response.data.success) {
      return {
        success: true,
        url: response.data.data.url,
        deleteUrl: response.data.data.delete_url,
        id: response.data.data.id,
      };
    } else {
      console.error(
        `❌ ImageBB upload failed for ${filename}:`,
        response.data.error
      );
      throw new Error(response.data.error?.message || "ImageBB upload failed");
    }
  } catch (error) {
    console.error(`❌ ImageBB upload error for ${filename}:`, error.message);
    return {
      success: false,
      error: error.message,
    };
  }
}

const port = process.env.PORT || 5000;

const store_id = process.env.STORE_ID;
const store_passwd = process.env.STORE_PASSWORD;
const is_live = false; //true for live, false for sandbox

const uri = process.env.MONGODB_URI;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

// Define collections globally so they can be accessed by all endpoints
const servicesCollection = client
  .db("SubidhaHomeService")
  .collection("services");
const usersCollection = client.db("SubidhaHomeService").collection("users");
const reviewsCollection = client.db("SubidhaHomeService").collection("reviews");

const paymentCollection = client
  .db("SubidhaHomeService")
  .collection("payments");

const staffCollection = client.db("SubidhaHomeService").collection("staffs");

const timeSlotCollection = client
  .db("SubidhaHomeService")
  .collection("timeSlots");

const notificationCollection = client
  .db("SubidhaHomeService")
  .collection("notifications");

const bookingCollection = client
  .db("SubidhaHomeService")
  .collection("bookings");

const providersCollection = client
  .db("SubidhaHomeService")
  .collection("providers");

const categoriesCollection = client
  .db("SubidhaHomeService")
  .collection("categories");

// Fallback function for service category names
// Provider helper functions removed

// Middleware to verify admin role using Firebase
const verifyAdmin = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ error: "No token provided" });
    }

    const idToken = authHeader.split(" ")[1];

    // Verify Firebase ID token
    const decodedToken = await admin.auth().verifyIdToken(idToken);

    // Check if user is admin
    const user = await usersCollection.findOne({ uid: decodedToken.uid });
    if (!user || user.role !== "admin") {
      return res.status(403).json({ error: "Admin access required" });
    }

    req.adminUser = user;
    next();
  } catch (error) {
    console.error("Firebase verification error:", error);
    res.status(401).json({ error: "Invalid token" });
  }
};

async function run() {
  try {
    // Connect to MongoDB
    await client.connect();
    console.log("✅ Connected to MongoDB successfully");

    const dailyTimeSlots = client
      .db("SubidhaHomeService")
      .collection("dailyTimeSlots");

    const rolesCollection = client.db("SubidhaHomeService").collection("roles");
    const categoriesCollection = client
      .db("SubidhaHomeService")
      .collection("categories");
    const providersCollection = client
      .db("SubidhaHomeService")
      .collection("providers");

    // Function to fetch service categories from database and format response
    const fetchServiceCategories = async (query = {}) => {
      try {
        const serviceCategories = await categoriesCollection
          .find(query)
          .sort({ _id: 1 })
          .toArray();

        return serviceCategories.map((serviceCategory) => ({
          _id: serviceCategory._id,
          serviceName: serviceCategory.serviceName,
          icon: serviceCategory.icon,
          isFeatured: serviceCategory.isFeatured,
          totalService: serviceCategory.totalService || 0,
        }));
      } catch (error) {
        console.error("Error fetching service categories:", error);
        throw new Error("Internal Server Error");
      }
    };

    // Endpoint to fetch all service categories with pagination, search, and sorting
    app.get("/serviceCategories", async (req, res) => {
      try {
        // Extract query parameters
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 10;
        const search = req.query.search || "";
        const sortBy = req.query.sortBy || "serviceName";
        const sortOrder = req.query.sortOrder || "asc";

        // Calculate skip value for pagination
        const skip = (page - 1) * limit;

        // Build query object for search
        let query = {};
        if (search) {
          query = {
            $or: [
              { serviceName: { $regex: search, $options: "i" } },
              { _id: { $regex: search, $options: "i" } },
            ],
          };
        }

        // Build sort object
        const sort = {};
        sort[sortBy] = sortOrder === "desc" ? -1 : 1;

        // Get total count for pagination
        const totalCategories = await categoriesCollection.countDocuments(
          query
        );

        // Fetch categories with pagination, search, and sorting
        const categories = await categoriesCollection
          .find(query)
          .sort(sort)
          .skip(skip)
          .limit(limit)
          .toArray();

        // Calculate actual service count for each category
        const categoriesWithServiceCount = await Promise.all(
          categories.map(async (category) => {
            const serviceCount = await servicesCollection.countDocuments({
              category: category._id.toString(),
            });
            return {
              ...category,
              totalService: serviceCount,
            };
          })
        );

        // Calculate total pages
        const totalPages = Math.ceil(totalCategories / limit);

        // Send paginated response
        res.send({
          categories: categoriesWithServiceCount,
          pagination: {
            currentPage: page,
            totalPages,
            totalCategories,
            limit,
            hasNextPage: page < totalPages,
            hasPreviousPage: page > 1,
          },
        });
      } catch (error) {
        console.error(error);
        res.status(500).send("Internal Server Error");
      }
    });

    // Endpoint to fetch a specific service category by ID
    app.get("/allServiceCategories/:id", async (req, res) => {
      try {
        const serviceId = req.params.id; // Extract the service ID from the request parameters
        const query = {
          _id: new ObjectId(serviceId), // Construct a query to find the service by its ObjectId
        };
        const service = await categoriesCollection.findOne(query); // Find the service in the collection
        res.send(service); // Send the fetched service category as a response
      } catch (error) {
        res.status(500).send("Internal Server Error"); // Handle any errors that occur during the fetch operation
      }
    });

    // Endpoint to update a category by ID - Admin only
    app.put("/edit-categories/:id", verifyAdmin, async (req, res) => {
      const categoryId = req.params.id; // Extract the category ID from the request parameters
      const data = req.body; // Extract the data to update from the request body
      const query = {
        _id: new ObjectId(categoryId), // Construct a query to find the category by its ObjectId
      };
      const updateDoc = {
        $set: {
          serviceName: data.serviceName, // Update the serviceName field with new value from data
          isFeatured: data.isFeatured, // Update the isFeatured field with new value from data
        },
      };
      if (data.icon) updateDoc.$set.icon = data.icon; // Conditionally update the icon field if present in data
      const options = { upsert: true }; // Options to perform an upsert if no document matches the query
      try {
        const result = await categoriesCollection.findOneAndUpdate(
          query,
          updateDoc,
          options
        ); // Perform the update operation
        res.send(result); // Send the result of the update operation as the response
      } catch (error) {
        console.error(error); // Log any errors to console
        res.status(500).send("Internal Server Error"); // Handle any errors with a 500 Internal Server Error response
      }
    });

    // Endpoint to add a new category - Admin only
    app.post("/add-category", verifyAdmin, async (req, res) => {
      try {
        const categoryData = req.body; // Extract category data from request body

        // Validate required fields
        if (!categoryData.serviceName || !categoryData.isFeatured) {
          return res
            .status(400)
            .send(
              "Missing required fields: serviceName and isFeatured are required"
            );
        }

        // Check if category with same name already exists
        const existingCategory = await categoriesCollection.findOne({
          serviceName: {
            $regex: new RegExp(`^${categoryData.serviceName}$`, "i"),
          },
        });

        if (existingCategory) {
          return res.status(409).send("Category with this name already exists");
        }

        // Create new category document
        const newCategory = {
          serviceName: categoryData.serviceName,
          icon: categoryData.icon || "",
          isFeatured: categoryData.isFeatured,
          serviceOverview: categoryData.serviceOverview || "",
          faq: categoryData.faq || [],
          createdAt: new Date(),
          updatedAt: new Date(),
        };

        // Insert the new category into the database
        const result = await categoriesCollection.insertOne(newCategory);

        if (result.insertedId) {
          res.status(201).send({
            message: "Category created successfully",
            categoryId: result.insertedId,
            category: newCategory,
          });
        } else {
          throw new Error("Failed to insert category");
        }
      } catch (error) {
        console.error("Error adding category:", error); // Log any errors to console
        res.status(500).send("Internal Server Error"); // Handle any errors with a 500 Internal Server Error response
      }
    });

    // Endpoint to delete a category - Admin only
    app.delete("/delete-category/:id", verifyAdmin, async (req, res) => {
      try {
        const categoryId = req.params.id; // Extract the category ID from request parameters

        const query = {
          _id: new ObjectId(categoryId), // Construct a query to find the category by its ObjectId
        };

        // Check if category exists
        const existingCategory = await categoriesCollection.findOne(query);
        if (!existingCategory) {
          return res.status(404).send("Category not found");
        }

        // Delete the category
        const result = await categoriesCollection.deleteOne(query);

        if (result.deletedCount > 0) {
          res.status(200).send({
            message: "Category deleted successfully",
            categoryId: categoryId,
          });
        } else {
          throw new Error("Failed to delete category");
        }
      } catch (error) {
        console.error("Error deleting category:", error); // Log any errors to console
        res.status(500).send("Internal Server Error"); // Handle any errors with a 500 Internal Server Error response
      }
    });

    // Endpoint to delete ALL categories

    // Endpoint to fetch users with optional search and pagination
    app.get("/users", async (req, res) => {
      try {
        const searchTerm = req.query.searchText; // Extract the 'searchText' query parameter from the request
        const page = req.query.page; // Extract the 'page' query parameter from the request
        const size = req.query.size; // Extract the 'size' query parameter from the request

        if (searchTerm) {
          // Check if 'searchText' parameter is provided in the request
          let users = await usersCollection.find().toArray(); // Fetch all users from the collection
          users = users?.filter((user) => {
            // Filter users based on search criteria
            return (
              user.userName?.toLowerCase().search(searchTerm.toLowerCase()) >
                -1 || // Check if userName contains searchTerm
              user.email?.toLowerCase().search(searchTerm.toLowerCase()) > -1 || // Check if email contains searchTerm
              user.phone?.toLowerCase().search(searchTerm.toLowerCase()) > -1 // Check if phone contains searchTerm
            );
          });
          const count = users.length; // Count the filtered users
          res.send({ users, count }); // Send filtered users and count as the response
          return;
        }

        // Pagination logic if no searchTerm is provided
        const users = await usersCollection // Fetch users with pagination
          .find()
          .skip(page * size) // Skip documents based on pagination parameters
          .limit(parseInt(size)) // Limit number of documents returned based on pagination parameters
          .toArray();
        const count = await usersCollection.estimatedDocumentCount(); // Count total number of users
        res.json({ users, count }); // Send paginated users and total count as the response
      } catch (error) {
        console.error(error); // Log any errors to console
        res.status(500).send("Internal Server Error"); // Handle any errors with a 500 Internal Server Error response
      }
    });

    // Endpoint to create or update a user
    app.post("/users", async (req, res) => {
      try {
        const user = req.body; // Extract the user object from the request body
        const query = {
          uid: user.uid, // Define a query to find the user by 'uid'
        };

        // Check if user already exists
        const existingUser = await usersCollection.findOne(query);

        if (existingUser) {
          // User exists - update only non-role fields to preserve admin role
          const updateData = { ...user };
          // Remove role from update if user already has a role (preserve admin roles)
          if (existingUser.role && existingUser.role !== "customer") {
            delete updateData.role;
          }

          const result = await usersCollection.findOneAndUpdate(
            query,
            { $set: updateData },
            { new: true }
          );
          res.send({ acknowledged: true, updated: true });
        } else {
          // New user - insert with default role
          const result = await usersCollection.insertOne(user);
          res.send({ acknowledged: true, created: true });
        }
      } catch (error) {
        console.error("Error creating user:", error); // Log any errors to console
        res.status(500).json({ error: "Internal server error" }); // Handle errors with a 500 Internal Server Error response
      }
    });

    // GET endpoint to fetch user details by UID
    app.get("/users/:uid", async (req, res) => {
      try {
        const uid = req.params.uid; // Extract UID from request parameters
        const query = { uid }; // Define query to find user by UID
        const user = await usersCollection.findOne(query); // Find user in collection
        res.json(user); // Send user details as JSON response
      } catch (error) {
        console.error(error); // Log any errors to console
        res.status(500).json({ message: "Internal server error" }); // Handle errors with 500 Internal Server Error response
      }
    });

    // POST endpoint to update user details by UID
    app.post("/users/:uid", async (req, res) => {
      try {
        const uid = req.params.uid; // Extract UID from request parameters
        const data = req.body; // Extract data to update from request body

        const filter = { uid }; // Define filter to find user by UID
        const options = { upsert: true }; // Define options for upsert (insert if not exists)

        const updateDoc = {
          $set: {
            [Object.keys(data)[0]]: Object.values(data)[0], // Update the first key-value pair from data
          },
        };

        const result = await usersCollection.updateOne(
          filter,
          updateDoc,
          options
        ); // Perform update operation
        res.send(result); // Send result of update operation as response
      } catch (error) {
        console.error(error); // Log any errors to console
        res.status(500).json({ message: "Internal server error" }); // Handle errors with 500 Internal Server Error response
      }
    });

    // DELETE endpoint to delete a user by ID (both Firebase and Database)
    app.delete("/users/:id", async (req, res) => {
      try {
        const userId = req.params.id; // Extract user ID from request parameters

        // Validate ObjectId format
        if (!ObjectId.isValid(userId)) {
          return res.status(400).json({
            success: false,
            error: "Invalid user ID format",
          });
        }

        // Find the user first to check if they exist
        const user = await usersCollection.findOne({
          _id: new ObjectId(userId),
        });

        if (!user) {
          return res.status(404).json({
            success: false,
            error: "User not found",
          });
        }

        let firebaseDeleted = false;
        let firebaseError = null;

        // Delete from Firebase first (if Firebase Admin SDK is available and user has uid)
        if (user.uid && admin.apps.length > 0) {
          try {
            await admin.auth().deleteUser(user.uid);
            firebaseDeleted = true;
          } catch (firebaseErr) {
            console.error("Error deleting Firebase user:", firebaseErr);
            firebaseError = firebaseErr.message;
            // Continue with database deletion even if Firebase deletion fails
          }
        } else if (user.uid && admin.apps.length === 0) {
          firebaseError = "Firebase Admin SDK not available";
        } else {
        }

        // Delete the user from the database
        const result = await usersCollection.deleteOne({
          _id: new ObjectId(userId),
        });

        if (result.deletedCount === 1) {
          const response = {
            success: true,
            message: "User deleted successfully",
            deletedUser: {
              id: userId,
              userName: user.userName,
              email: user.email,
            },
            deletionDetails: {
              database: true,
              firebase: firebaseDeleted,
            },
          };

          // Add warning if Firebase deletion failed
          if (user.uid && !firebaseDeleted) {
            response.warning = `Database deleted but Firebase deletion failed: ${
              firebaseError || "Unknown error"
            }`;
          }

          res.json(response);
        } else {
          res.status(500).json({
            success: false,
            error: "Failed to delete user from database",
          });
        }
      } catch (error) {
        console.error("Error deleting user:", error); // Log any errors to console
        res.status(500).json({
          success: false,
          error: "Internal server error",
        }); // Handle errors with 500 Internal Server Error response
      }
    });

    app.put("/update-status/:uid", async (req, res) => {
      try {
        const uid = req.params.uid; // Extract UID from request parameters
        const status = req.body.status; // Extract status from request body

        const filter = { uid }; // Define filter to find user by UID
        const updateDoc = {
          $set: { status }, // Update status field in user document
        };
        const options = { upsert: true }; // Define options for upsert (insert if not exists)

        const result = await usersCollection.updateOne(
          filter,
          updateDoc,
          options
        ); // Perform update operation
        res.json(result); // Send result of update operation as JSON response
      } catch (error) {
        console.error("Error updating status:", error); // Log any errors to console
        res.status(500).json({ message: "Internal server error" }); // Handle errors with 500 Internal Server Error response
      }
    });

    app.put("/user/update-image/:uid", async (req, res) => {
      const userId = req.params.uid; // Extract UID from request parameters
      const { photoURL } = req.body.photoURL; // Extract photoURL from request body

      try {
        const updateResult = await usersCollection.updateOne(
          { uid: userId },
          { $set: { photoURL } }
        );
        res.json(updateResult); // Send update result as JSON response
      } catch (err) {
        console.error("Error updating image:", err); // Log any errors to console
        res.status(500).json({ message: "Internal server error" }); // Handle errors with 500 Internal Server Error response
      }
    });

    // PATCH endpoint to update user role by UID
    app.patch("/users/admin/:uid", async (req, res) => {
      const uid = req.params.uid; // Extract UID from URL parameters
      const { role } = req.body; // Extract role from request body
      try {
        const filter = { uid }; // Define filter to find user by UID
        const updateDoc = {
          $set: { role }, // Update role field in user document
        };
        const result = await usersCollection.updateOne(filter, updateDoc); // Perform update operation
        res.send(result); // Send result of update operation
      } catch (err) {
        res.status(500).json({ message: "Internal server error" }); // Handle errors with 500 Internal Server Error response
      }
    });

    // GET endpoint to check if user is an admin by UID
    app.get("/users/admin/:uid", async (req, res) => {
      try {
        const uid = req.params.uid; // Extract UID from URL parameters
        const query = { uid }; // Define query to find user by UID
        const user = await usersCollection.findOne(query); // Find user in collection

        // Convert role to lowercase for case-insensitive comparison
        const role = user?.role?.toLowerCase();

        // Check if user is admin, sub admin, or super admin
        const isAdmin =
          role === "admin" || role === "sub admin" || role === "super admin";

        res.send({ isAdmin }); // Send whether user is admin as JSON response
      } catch (error) {
        console.error("Error fetching user:", error); // Log any errors to console
        res.status(500).send({ error: "Internal Server Error" }); // Handle errors with 500 Internal Server Error response
      }
    });

    // Advanced Users API Endpoints

    // GET endpoint for advanced user search with filters and sorting
    app.get("/api/users/advanced", verifyAdmin, async (req, res) => {
      try {
        const {
          page = 1,
          limit = 30,
          search = "",
          role = "all",
          status = "all",
          sortBy = "signupDate",
          sortOrder = "desc",
        } = req.query;

        // Build query object
        let query = {};

        // Search filter
        if (search) {
          query.$or = [
            { userName: { $regex: search, $options: "i" } },
            { email: { $regex: search, $options: "i" } },
            { phone: { $regex: search, $options: "i" } },
          ];
        }

        // Role filter
        if (role !== "all") {
          query.role = role;
        }

        // Status filter
        if (status !== "all") {
          query.status = status;
        }

        // Build sort object
        const sort = {};
        sort[sortBy] = sortOrder === "desc" ? -1 : 1;

        // Calculate pagination
        const skip = (parseInt(page) - 1) * parseInt(limit);

        // Get total count
        const totalCount = await usersCollection.countDocuments(query);

        // Fetch users with pagination and sorting
        const users = await usersCollection
          .find(query)
          .sort(sort)
          .skip(skip)
          .limit(parseInt(limit))
          .toArray();

        // Add placeholder image for users without photoURL
        const placeholderImage =
          "https://via.placeholder.com/150x150/cccccc/666666?text=User";
        const usersWithPlaceholder = users.map((user) => ({
          ...user,
          photoURL:
            user.photoURL && user.photoURL.trim() !== ""
              ? user.photoURL
              : placeholderImage,
        }));

        // Calculate pagination info
        const totalPages = Math.ceil(totalCount / parseInt(limit));

        res.json({
          users: usersWithPlaceholder,
          pagination: {
            currentPage: parseInt(page),
            totalPages,
            totalCount,
            limit: parseInt(limit),
            hasNextPage: parseInt(page) < totalPages,
            hasPreviousPage: parseInt(page) > 1,
          },
        });
      } catch (error) {
        console.error("Error in advanced users search:", error);
        res.status(500).json({ error: "Internal Server Error" });
      }
    });

    // PATCH endpoint for bulk role updates
    app.patch("/api/users/bulk-roles", async (req, res) => {
      try {
        const { userIds, role } = req.body;

        if (!userIds || !Array.isArray(userIds) || userIds.length === 0) {
          return res.status(400).json({ error: "User IDs array is required" });
        }

        if (!role) {
          return res.status(400).json({ error: "Role is required" });
        }

        const result = await usersCollection.updateMany(
          { _id: { $in: userIds.map((id) => new ObjectId(id)) } },
          { $set: { role } }
        );

        res.json({
          success: true,
          modifiedCount: result.modifiedCount,
          message: `Updated ${result.modifiedCount} users to ${role} role`,
        });
      } catch (error) {
        console.error("Error in bulk role update:", error);
        res.status(500).json({ error: "Internal Server Error" });
      }
    });

    // DELETE endpoint for bulk user deletion
    app.delete("/api/users/bulk-delete", verifyAdmin, async (req, res) => {
      try {
        const { userIds } = req.body;

        if (!userIds || !Array.isArray(userIds) || userIds.length === 0) {
          return res.status(400).json({ error: "User IDs array is required" });
        }

        const result = await usersCollection.deleteMany({
          _id: { $in: userIds.map((id) => new ObjectId(id)) },
        });

        res.json({
          success: true,
          deletedCount: result.deletedCount,
          message: `Deleted ${result.deletedCount} users`,
        });
      } catch (error) {
        console.error("Error in bulk user deletion:", error);
        res.status(500).json({ error: "Internal Server Error" });
      }
    });

    // POST endpoint to create a new user
    app.post("/api/users", verifyAdmin, async (req, res) => {
      try {
        const { userName, email, phone, password, role, status } = req.body;

        // Validate required fields
        if (!userName || !email || !password) {
          return res.status(400).json({
            error: "Name, email, and password are required",
          });
        }

        if (password.length < 6) {
          return res.status(400).json({
            error: "Password must be at least 6 characters long",
          });
        }

        // Check if user already exists in database
        const existingUser = await usersCollection.findOne({ email });
        if (existingUser) {
          return res.status(400).json({
            error: "User with this email already exists",
          });
        }

        let firebaseUser = null;
        let firebaseError = null;

        // Create user in Firebase first (if Firebase Admin SDK is available)
        if (admin.apps.length > 0) {
          try {
            firebaseUser = await admin.auth().createUser({
              email: email,
              password: password,
              displayName: userName,
              emailVerified: false,
            });

            console.log(`Firebase user created: ${firebaseUser.uid}`);
          } catch (firebaseErr) {
            console.error("Error creating Firebase user:", firebaseErr);
            firebaseError = firebaseErr.message;
            // Continue with database creation even if Firebase creation fails
          }
        } else {
          console.log(
            "Firebase Admin SDK not initialized - skipping Firebase user creation"
          );
          firebaseError = "Firebase Admin SDK not available";
        }

        // Create new user object
        const newUser = {
          uid: firebaseUser?.uid || null,
          userName,
          email,
          phone: phone || "",
          role: role || "customer",
          status: status || "Active",
          isVerified: false,
          signupDate: new Date(),
          lastLogin: null,
          photoURL: "",
        };

        // Insert user into database
        const result = await usersCollection.insertOne(newUser);

        const response = {
          success: true,
          message: "User created successfully",
          user: {
            _id: result.insertedId,
            ...newUser,
          },
          creationDetails: {
            database: true,
            firebase: !!firebaseUser,
          },
        };

        // Add warning if Firebase creation failed
        if (!firebaseUser && firebaseError) {
          response.warning = `Database created but Firebase creation failed: ${firebaseError}`;
        }

        res.status(201).json(response);
      } catch (error) {
        console.error("Error creating user:", error);
        res.status(500).json({ error: "Internal Server Error" });
      }
    });

    // GET endpoint for user statistics
    app.get("/api/users/statistics", async (req, res) => {
      try {
        const totalUsers = await usersCollection.countDocuments();

        const roleStats = await usersCollection
          .aggregate([{ $group: { _id: "$role", count: { $sum: 1 } } }])
          .toArray();

        const statusStats = await usersCollection
          .aggregate([{ $group: { _id: "$status", count: { $sum: 1 } } }])
          .toArray();

        const recentSignups = await usersCollection
          .find({})
          .sort({ signupDate: -1 })
          .limit(5)
          .toArray();

        res.json({
          totalUsers,
          roleStats,
          statusStats,
          recentSignups,
        });
      } catch (error) {
        console.error("Error fetching user statistics:", error);
        res.status(500).json({ error: "Internal Server Error" });
      }
    });

    // GET endpoint for user export data
    app.get("/api/users/export", async (req, res) => {
      try {
        const { format = "json" } = req.query;

        const users = await usersCollection.find({}).toArray();

        if (format === "csv") {
          // Convert to CSV format
          const csvHeader =
            "Name,Email,Phone,Role,Status,Signup Date,Last Login\n";
          const csvData = users
            .map(
              (user) =>
                `"${user.userName || "N/A"}","${user.email || "N/A"}","${
                  user.phone || "N/A"
                }","${user.role || "N/A"}","${user.status || "N/A"}","${
                  user.signupDate || "N/A"
                }","${user.lastLogin || "N/A"}"`
            )
            .join("\n");

          res.setHeader("Content-Type", "text/csv");
          res.setHeader(
            "Content-Disposition",
            "attachment; filename=users-export.csv"
          );
          res.send(csvHeader + csvData);
        } else {
          res.json(users);
        }
      } catch (error) {
        console.error("Error exporting users:", error);
        res.status(500).json({ error: "Internal Server Error" });
      }
    });

    // GET endpoint to fetch admin statistics
    app.get("/api/statistics", async (req, res) => {
      try {
        // Get counts from different collections
        const totalUsers = await usersCollection.countDocuments({
          role: { $ne: "admin" },
        });
        const totalCategories = await categoriesCollection.countDocuments();

        const statistics = {
          totalUsers,
          totalCategories,
        };

        res.json(statistics);
      } catch (error) {
        console.error("Error fetching statistics:", error);
        res.status(500).json({ error: "Internal Server Error" });
      }
    });

    // Provider endpoints removed

    // Provider details endpoint removed

    // GET endpoint to fetch reviews for a provider
    app.get("/reviews/:providerId", async (req, res) => {
      const providerID = req.params.providerId; // Extract provider ID from URL parameters

      try {
        const query = { providerID }; // Define query to find reviews by provider ID
        const reviews = await reviewsCollection
          .find(query) // Find reviews in reviews collection
          .sort({ _id: -1 }) // Sort reviews by descending order of _id (assuming it represents time)
          .toArray(); // Convert results to array

        res.send(reviews); // Send reviews as JSON response
      } catch (error) {
        console.error("Error fetching reviews:", error); // Log any errors to console
        res.status(500).json({ error: "Internal Server Error" }); // Handle errors with 500 Internal Server Error response
      }
    });

    // GET endpoint to fetch reviews by user ID (uid)
    app.get("/user-reviews/:uid", async (req, res) => {
      const userID = req.params.uid; // Extract userID from URL parameters

      try {
        const query = { userID }; // Define query to find reviews by userID
        const reviews = await reviewsCollection.find(query).toArray(); // Fetch reviews from reviewsCollection

        res.send(reviews); // Send reviews as JSON response
      } catch (error) {
        console.error("Error fetching user reviews:", error); // Log any errors to console
        res.status(500).json({ error: "Internal Server Error" }); // Handle errors with 500 Internal Server Error response
      }
    });

    // POST endpoint to create a new review
    app.post("/reviews", async (req, res) => {
      try {
        const reviewData = req.body; // Extract review data from request body

        // Check if user has already reviewed this order
        const existingReview = await reviewsCollection.findOne({
          userID: reviewData.userID,
          bookingId: reviewData.bookingId,
        });

        if (existingReview) {
          return res.status(400).json({
            error: "You have already reviewed this order",
            message: "You can only review an order once",
          });
        }

        // Add timestamp if not provided
        if (!reviewData.createdAt) {
          reviewData.createdAt = new Date().toISOString();
        }

        // Insert the review into the reviews collection
        const result = await reviewsCollection.insertOne(reviewData);

        if (result.acknowledged) {
          res.status(201).json({
            message: "Review created successfully",
            reviewId: result.insertedId,
            acknowledged: true,
          });
        } else {
          res.status(500).json({ error: "Failed to create review" });
        }
      } catch (error) {
        console.error("Error creating review:", error);
        res.status(500).json({ error: "Internal Server Error" });
      }
    });

    // PUT endpoint to update a review
    app.put("/reviews/:reviewId", async (req, res) => {
      try {
        const reviewId = req.params.reviewId;
        const updateData = req.body;

        // Add updated timestamp
        updateData.updatedAt = new Date().toISOString();

        const result = await reviewsCollection.updateOne(
          { _id: new ObjectId(reviewId) },
          { $set: updateData }
        );

        if (result.matchedCount === 0) {
          return res.status(404).json({ error: "Review not found" });
        }

        if (result.modifiedCount > 0) {
          res.json({
            message: "Review updated successfully",
            acknowledged: true,
          });
        } else {
          res.status(500).json({ error: "Failed to update review" });
        }
      } catch (error) {
        console.error("Error updating review:", error);
        res.status(500).json({ error: "Internal Server Error" });
      }
    });

    // DELETE endpoint to delete a review
    app.delete("/reviews/:reviewId", async (req, res) => {
      try {
        const reviewId = req.params.reviewId;

        const result = await reviewsCollection.deleteOne({
          _id: new ObjectId(reviewId),
        });

        if (result.deletedCount === 0) {
          return res.status(404).json({ error: "Review not found" });
        }

        res.json({
          message: "Review deleted successfully",
          acknowledged: true,
        });
      } catch (error) {
        console.error("Error deleting review:", error);
        res.status(500).json({ error: "Internal Server Error" });
      }
    });

    // GET endpoint to fetch all reviews (for testing)
    app.get("/reviews/all", async (req, res) => {
      try {
        const reviews = await reviewsCollection.find({}).toArray();
        console.log(`Total reviews in database: ${reviews.length}`);
        res.json(reviews);
      } catch (error) {
        console.error("Error fetching all reviews:", error);
        res.status(500).json({ error: "Internal Server Error" });
      }
    });

    // GET endpoint to fetch reviews for a specific service
    app.get("/reviews/service/:serviceId", async (req, res) => {
      const serviceId = req.params.serviceId; // Extract service ID from URL parameters

      try {
        // First, let's get the service details to match by service name
        const service = await servicesCollection.findOne({
          _id: new ObjectId(serviceId),
        });

        const query = {
          $or: [
            { serviceId: serviceId },
            { serviceName: service?.serviceName },
            { service: service?.serviceName },
            { bookingId: serviceId },
            { orderId: serviceId },
            // Also try matching by service ID as string
            { serviceId: serviceId.toString() },
          ],
        }; // Define query to find reviews by service ID or name

        console.log("Searching for reviews with query:", query); // Debug log

        const reviews = await reviewsCollection
          .find(query)
          .sort({ createdAt: -1 }) // Sort by creation date, newest first
          .toArray();

        console.log(`Found ${reviews.length} reviews for service ${serviceId}`); // Debug log

        res.json(reviews); // Send reviews as JSON response
      } catch (error) {
        console.error("Error fetching service reviews:", error);
        res.status(500).json({ error: "Internal Server Error" });
      }
    });

    // GET endpoint to check if user has reviewed a specific order
    app.get("/reviews/check/:userId/:bookingId", async (req, res) => {
      try {
        const { userId, bookingId } = req.params;

        const existingReview = await reviewsCollection.findOne({
          userID: userId,
          bookingId: bookingId,
        });

        res.json({
          hasReviewed: !!existingReview,
          review: existingReview || null,
        });
      } catch (error) {
        console.error("Error checking review status:", error);
        res.status(500).json({ error: "Internal Server Error" });
      }
    });

    // GET endpoint to fetch user orders
    app.get("/user-orders/:uid", async (req, res) => {
      const userID = req.params.uid; // Extract userID from URL parameters

      try {
        console.log("🔍 Searching for orders with userID:", userID);

        // Try multiple field names that might exist in the database
        const query = {
          $or: [
            { userID: userID },
            { userId: userID },
            { customerId: userID },
            { customerID: userID },
          ],
        };

        const orders = await bookingCollection.find(query).toArray(); // Fetch orders from bookingCollection
        console.log("📋 Found orders:", orders.length);

        res.json(orders); // Send orders as JSON response
      } catch (error) {
        console.error("Error fetching user orders:", error);
        res.status(500).json({ error: "Internal Server Error" });
      }
    });

    // POST endpoint to edit or update provider service details
    app.post("/edit-provider-service/:providerId", async (req, res) => {
      const providerId = req.params.providerId; // Extract providerId from URL parameters
      const { editService } = req.body; // Extract editService object from request body

      try {
        const provider = await providersCollection.findOne({ uid: providerId }); // Find provider by uid

        if (provider) {
          if (provider.myServices && provider.myServices.length > 0) {
            // Update existing service if found
            const matchedService = provider.myServices.find(
              (service) => service.serviceName === editService.serviceName
            );

            if (matchedService) {
              // Update existing matched service
              matchedService.amount = editService.amount;
              matchedService.details = editService.details;
              matchedService.title = editService.title;

              // Check if selectedFileURL has changed
              if (
                matchedService.selectedFileURL !== editService.selectedFileURL
              ) {
                matchedService.selectedFileURL = editService.selectedFileURL;
              }

              // Filter out updated service from rest of services
              const restServices = provider.myServices.filter(
                (service) => service.serviceName !== editService.serviceName
              );

              // Update provider document with updated services array
              const result = await providersCollection.findOneAndUpdate(
                { uid: providerId },
                { $set: { myServices: [...restServices, matchedService] } },
                { returnOriginal: false }
              );

              return res.send(result); // Send updated result as response
            } else {
              // Update services array by adding new service
              const restServices = provider.myServices.filter(
                (service) => service.serviceName !== editService.serviceName
              );
              const result = await providersCollection.findOneAndUpdate(
                { uid: providerId },
                { $set: { myServices: [...restServices, editService] } },
                { returnOriginal: false }
              );

              return res.send(result); // Send updated result as response
            }
          } else {
            // Create new services array if provider has no services yet
            const result = await providersCollection.findOneAndUpdate(
              { uid: providerId },
              { $set: { myServices: [editService] } },
              { returnOriginal: false }
            );

            return res.json(result); // Send updated result as JSON response
          }
        } else {
          res.status(404).json({ error: "Provider not found" }); // Return error if provider not found
        }
      } catch (error) {
        console.error("Error updating provider service:", error); // Log any errors to console
        res.status(500).json({ error: "Internal Server Error" }); // Handle errors with 500 Internal Server Error response
      }
    });

    // POST endpoint to fetch a specific service provided by a provider
    app.post("/provider-service/:providerId", async (req, res) => {
      const providerId = req.params.providerId; // Extract providerId from URL parameters
      const { serviceName } = req.body; // Extract serviceName from request body

      try {
        const provider = await providersCollection.findOne({ uid: providerId }); // Find provider by uid

        if (provider?.myServices) {
          // Search for a service with matching serviceName in provider's myServices array
          const matchedService = provider.myServices.find(
            (service) => service.serviceName === serviceName
          );

          return res.send(matchedService); // Send matchedService if found
        }

        res.send({}); // Send empty object if provider or myServices array not found
      } catch (error) {
        console.error("Error fetching provider service:", error); // Log any errors to console
        res.status(500).json({ error: "Internal Server Error" }); // Handle errors with 500 Internal Server Error response
      }
    });

    app.post("/roles", async (req, res) => {
      const { roleName, permissions } = req.body;

      // Validate request body
      if (!roleName || !Array.isArray(permissions)) {
        return res.status(400).send({ message: "Invalid data format" });
      }

      const role = {
        roleName,
        permissions,
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      try {
        // Update or insert the role in the rolesCollection
        const filter = {
          roleName: { $regex: new RegExp(`^${roleName}$`, "i") },
        }; // Case insensitive match for roleName
        const updateDocument = {
          $set: {
            roleName: role.roleName,
            permissions: role.permissions,
            updatedAt: new Date(),
          },
        };
        const options = { upsert: true, returnOriginal: false }; // Upsert if not found, return updated document

        const result = await rolesCollection.findOneAndUpdate(
          filter,
          updateDocument,
          options
        );

        // Check if the role was updated or inserted
        if (result.lastErrorObject.updatedExisting) {
          res.send({ message: "Role updated successfully" });
        } else {
          res.send({ message: "Role inserted successfully" });
        }
      } catch (error) {
        console.error("Failed to create or update role:", error);
        res.status(500).send({ message: "Failed to create or update role" });
      }
    });

    app.get("/roles", async (req, res) => {
      try {
        const query = {};
        const result = await rolesCollection.find(query).toArray();
        res.send(result);
      } catch (error) {
        res.status(500).json({ error: "Internal server error" });
      }
    });

    function sendEmail({
      email,
      subject,
      message,
      userName,
      invoiceNo,
      invoiceDate,
      totalAmount,
      serviceQuantity,
      unitCost,
      service,
    }) {
      console.log("user email", email);
      return new Promise((resolve, reject) => {
        var transporter = nodemailer.createTransport({
          service: "gmail",
          auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS,
          },
        });

        const mail_configs = {
          from: process.env.EMAIL_USER,
          to: email,
          subject: subject,
          html: `
          <!DOCTYPE HTML PUBLIC "-//W3C//DTD XHTML 1.0 Transitional //EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
          <html xmlns="http://www.w3.org/1999/xhtml" xmlns:v="urn:schemas-microsoft-com:vml" xmlns:o="urn:schemas-microsoft-com:office:office">
          <head>
          <!--[if gte mso 9]>
          <xml>
            <o:OfficeDocumentSettings>
              <o:AllowPNG/>
              <o:PixelsPerInch>96</o:PixelsPerInch>
            </o:OfficeDocumentSettings>
          </xml>
          <![endif]-->
            <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <meta name="x-apple-disable-message-reformatting">
            <!--[if !mso]><!--><meta http-equiv="X-UA-Compatible" content="IE=edge"><!--<![endif]-->
            <title></title>
            
              <style type="text/css">
                @media only screen and (min-width: 620px) {
            .u-row {
              width: 600px !important;
            }
            .u-row .u-col {
              vertical-align: top;
            }
          
            .u-row .u-col-31 {
              width: 186px !important;
            }
          
            .u-row .u-col-31p5 {
              width: 189px !important;
            }
          
            .u-row .u-col-33p33 {
              width: 199.98px !important;
            }
          
            .u-row .u-col-35p67 {
              width: 214.02px !important;
            }
          
            .u-row .u-col-68p5 {
              width: 411px !important;
            }
          
            .u-row .u-col-100 {
              width: 600px !important;
            }
          
          }
          
          @media (max-width: 620px) {
            .u-row-container {
              max-width: 100% !important;
              padding-left: 0px !important;
              padding-right: 0px !important;
            }
            .u-row .u-col {
              min-width: 320px !important;
              max-width: 100% !important;
              display: block !important;
            }
            .u-row {
              width: 100% !important;
            }
            .u-col {
              width: 100% !important;
            }
            .u-col > div {
              margin: 0 auto;
            }
          }
          body {
            margin: 0;
            padding: 0;
          }
          
          table,
          tr,
          td {
            vertical-align: top;
            border-collapse: collapse;
          }
          
          p {
            margin: 0;
          }
          
          .ie-container table,
          .mso-container table {
            table-layout: fixed;
          }
          
          * {
            line-height: inherit;
          }
          
          a[x-apple-data-detectors='true'] {
            color: inherit !important;
            text-decoration: none !important;
          }
          
          table, td { color: #000000; } #u_body a { color: #0000ee; text-decoration: underline; } @media (max-width: 480px) { #u_content_text_14 .v-container-padding-padding { padding: 15px 10px !important; } #u_content_text_15 .v-container-padding-padding { padding: 10px !important; } #u_content_text_26 .v-text-align { text-align: center !important; } #u_content_text_27 .v-text-align { text-align: center !important; } #u_content_text_28 .v-container-padding-padding { padding: 25px 10px 0px !important; } }
              </style>
            
            
          
          <!--[if !mso]><!--><link href="https://fonts.googleapis.com/css?family=Cabin:400,700&display=swap" rel="stylesheet" type="text/css"><link href="https://fonts.googleapis.com/css?family=Lobster+Two:400,700&display=swap" rel="stylesheet" type="text/css"><!--<![endif]-->
          
          </head>
          
          <body class="clean-body u_body" style="margin: 0;padding: 0;-webkit-text-size-adjust: 100%;background-color: #dfdfdf;color: #000000">
            <!--[if IE]><div class="ie-container"><![endif]-->
            <!--[if mso]><div class="mso-container"><![endif]-->
            <table id="u_body" style="border-collapse: collapse;table-layout: fixed;border-spacing: 0;mso-table-lspace: 0pt;mso-table-rspace: 0pt;vertical-align: top;min-width: 320px;Margin: 0 auto;background-color: #dfdfdf;width:100%" cellpadding="0" cellspacing="0">
            <tbody>
            <tr style="vertical-align: top">
              <td style="word-break: break-word;border-collapse: collapse !important;vertical-align: top">
              <!--[if (mso)|(IE)]><table width="100%" cellpadding="0" cellspacing="0" border="0"><tr><td align="center" style="background-color: #dfdfdf;"><![endif]-->
              
            
            
              <!--[if gte mso 9]>
                <table cellpadding="0" cellspacing="0" border="0" style="margin: 0 auto;min-width: 320px;max-width: 600px;">
                  <tr>
                    <td background="https://cdn.templates.unlayer.com/assets/1619158063039-mo.jpg" valign="top" width="100%">
                <v:rect xmlns:v="urn:schemas-microsoft-com:vml" fill="true" stroke="false" style="width: 600px;">
                  <v:fill type="frame" src="https://cdn.templates.unlayer.com/assets/1619158063039-mo.jpg" /><v:textbox style="mso-fit-shape-to-text:true" inset="0,0,0,0">
                <![endif]-->
            
          <div class="u-row-container" style="padding: 0px;background-image: url('https://i.ibb.co/xGhDWMj/image-8.jpg');background-repeat: no-repeat;background-position: center top;background-color: #dfdfdf">
            <div class="u-row" style="margin: 0 auto;min-width: 320px;max-width: 600px;overflow-wrap: break-word;word-wrap: break-word;word-break: break-word;background-color: transparent;">
              <div style="border-collapse: collapse;display: table;width: 100%;height: 100%;background-color: transparent;">
                <!--[if (mso)|(IE)]><table width="100%" cellpadding="0" cellspacing="0" border="0"><tr><td style="padding: 0px;background-image: url('images/image-8.jpeg');background-repeat: no-repeat;background-position: center top;background-color: #dfdfdf;" align="center"><table cellpadding="0" cellspacing="0" border="0" style="width:600px;"><tr style="background-color: transparent;"><![endif]-->
                
          <!--[if (mso)|(IE)]><td align="center" width="600" style="width: 600px;padding: 0px;border-top: 0px solid transparent;border-left: 0px solid transparent;border-right: 0px solid transparent;border-bottom: 0px solid transparent;" valign="top"><![endif]-->
          <div class="u-col u-col-100" style="max-width: 320px;min-width: 600px;display: table-cell;vertical-align: top;">
            <div style="height: 100%;width: 100% !important;">
            <!--[if (!mso)&(!IE)]><!--><div style="box-sizing: border-box; height: 100%; padding: 0px;border-top: 0px solid transparent;border-left: 0px solid transparent;border-right: 0px solid transparent;border-bottom: 0px solid transparent;"><!--<![endif]-->
            
          <table style="font-family:arial,helvetica,sans-serif;" role="presentation" cellpadding="0" cellspacing="0" width="100%" border="0">
            <tbody>
              <tr>
                <td class="v-container-padding-padding" style="overflow-wrap:break-word;word-break:break-word;padding:65px 10px 10px;font-family:arial,helvetica,sans-serif;" align="left">
                  
            <div class="v-text-align" style="font-size: 14px; color: #ffffff; line-height: 150%; text-align: center; word-wrap: break-word;">
              <p style="font-size: 14px; line-height: 150%; text-align: center;"><span style="font-size: 36px; line-height: 54px;">Dear <span style="font-family: Cabin, sans-serif; line-height: 54px; color: #24771f; background-color: #ffffff; font-size: 36px;"><strong data-sider-select-id="7f73138d-be89-4f56-91ff-74ec17744b63"> ${userName} </strong></span></span></p>
            </div>
          
                </td>
              </tr>
            </tbody>
          </table>
          
          <table style="font-family:arial,helvetica,sans-serif;" role="presentation" cellpadding="0" cellspacing="0" width="100%" border="0">
            <tbody>
              <tr>
                <td class="v-container-padding-padding" style="overflow-wrap:break-word;word-break:break-word;padding:0px 10px 40px;font-family:arial,helvetica,sans-serif;" align="left">
                  
            <div class="v-text-align" style="font-size: 14px; color: #ffffff; line-height: 140%; text-align: center; word-wrap: break-word;">
              <p style="font-size: 14px; line-height: 140%;"><span style="font-size: 24px; line-height: 33.6px;">THANKS FOR YOUR PAYMENT!</span></p>
            </div>
          
                </td>
              </tr>
            </tbody>
          </table>
          
            <!--[if (!mso)&(!IE)]><!--></div><!--<![endif]-->
            </div>
          </div>
          <!--[if (mso)|(IE)]></td><![endif]-->
                <!--[if (mso)|(IE)]></tr></table></td></tr></table><![endif]-->
              </div>
            </div>
            </div>
            
              <!--[if gte mso 9]>
                </v:textbox></v:rect>
              </td>
              </tr>
              </table>
              <![endif]-->
              
          
          
            
            
          <div class="u-row-container" style="padding: 0px;background-color: transparent">
            <div class="u-row" style="margin: 0 auto;min-width: 320px;max-width: 600px;overflow-wrap: break-word;word-wrap: break-word;word-break: break-word;background-color: #ebebeb;">
              <div style="border-collapse: collapse;display: table;width: 100%;height: 100%;background-color: transparent;">
                <!--[if (mso)|(IE)]><table width="100%" cellpadding="0" cellspacing="0" border="0"><tr><td style="padding: 0px;background-color: transparent;" align="center"><table cellpadding="0" cellspacing="0" border="0" style="width:600px;"><tr style="background-color: #ebebeb;"><![endif]-->
                
          <!--[if (mso)|(IE)]><td align="center" width="600" style="width: 600px;padding: 0px;border-top: 0px solid transparent;border-left: 0px solid transparent;border-right: 0px solid transparent;border-bottom: 0px solid transparent;" valign="top"><![endif]-->
          <div class="u-col u-col-100" style="max-width: 320px;min-width: 600px;display: table-cell;vertical-align: top;">
            <div style="height: 100%;width: 100% !important;">
            <!--[if (!mso)&(!IE)]><!--><div style="box-sizing: border-box; height: 100%; padding: 0px;border-top: 0px solid transparent;border-left: 0px solid transparent;border-right: 0px solid transparent;border-bottom: 0px solid transparent;"><!--<![endif]-->
            
          <table style="font-family:arial,helvetica,sans-serif;" role="presentation" cellpadding="0" cellspacing="0" width="100%" border="0">
            <tbody>
              <tr>
                <td class="v-container-padding-padding" style="overflow-wrap:break-word;word-break:break-word;padding:10px;font-family:arial,helvetica,sans-serif;" align="left">
                  
            <table height="0px" align="center" border="0" cellpadding="0" cellspacing="0" width="100%" style="border-collapse: collapse;table-layout: fixed;border-spacing: 0;mso-table-lspace: 0pt;mso-table-rspace: 0pt;vertical-align: top;border-top: 0px solid #BBBBBB;-ms-text-size-adjust: 100%;-webkit-text-size-adjust: 100%">
              <tbody>
                <tr style="vertical-align: top">
                  <td style="word-break: break-word;border-collapse: collapse !important;vertical-align: top;font-size: 0px;line-height: 0px;mso-line-height-rule: exactly;-ms-text-size-adjust: 100%;-webkit-text-size-adjust: 100%">
                    <span>&#160;</span>
                  </td>
                </tr>
              </tbody>
            </table>
          
                </td>
              </tr>
            </tbody>
          </table>
          
            <!--[if (!mso)&(!IE)]><!--></div><!--<![endif]-->
            </div>
          </div>
          <!--[if (mso)|(IE)]></td><![endif]-->
                <!--[if (mso)|(IE)]></tr></table></td></tr></table><![endif]-->
              </div>
            </div>
            </div>
            
          
          
            
            
          <div class="u-row-container" style="padding: 0px;background-color: transparent">
            <div class="u-row" style="margin: 0 auto;min-width: 320px;max-width: 600px;overflow-wrap: break-word;word-wrap: break-word;word-break: break-word;background-color: #ebebeb;">
              <div style="border-collapse: collapse;display: table;width: 100%;height: 100%;background-color: transparent;">
                <!--[if (mso)|(IE)]><table width="100%" cellpadding="0" cellspacing="0" border="0"><tr><td style="padding: 0px;background-color: transparent;" align="center"><table cellpadding="0" cellspacing="0" border="0" style="width:600px;"><tr style="background-color: #ebebeb;"><![endif]-->
                
          <!--[if (mso)|(IE)]><td align="center" width="198" style="width: 198px;padding: 0px;border-top: 0px solid transparent;border-left: 0px solid transparent;border-right: 1px solid #e1e1e1;border-bottom: 0px solid transparent;" valign="top"><![endif]-->
          <div class="u-col u-col-33p33" style="max-width: 320px;min-width: 199.98px;display: table-cell;vertical-align: top;">
            <div style="height: 100%;width: 100% !important;">
            <!--[if (!mso)&(!IE)]><!--><div style="box-sizing: border-box; height: 100%; padding: 0px;border-top: 0px solid transparent;border-left: 0px solid transparent;border-right: 1px solid #e1e1e1;border-bottom: 0px solid transparent;"><!--<![endif]-->
            
          <table style="font-family:arial,helvetica,sans-serif;" role="presentation" cellpadding="0" cellspacing="0" width="100%" border="0">
            <tbody>
              <tr>
                <td class="v-container-padding-padding" style="overflow-wrap:break-word;word-break:break-word;padding:20px 10px 0px;font-family:arial,helvetica,sans-serif;" align="left">
                  
          <table width="100%" cellpadding="0" cellspacing="0" border="0">
            <tr>
              <td class="v-text-align" style="padding-right: 0px;padding-left: 0px;" align="center">
                
                <img align="center" border="0" src="https://i.ibb.co/r722fC0/image-6.jpg" alt="Mark" title="Mark" style="outline: none;text-decoration: none;-ms-interpolation-mode: bicubic;clear: both;display: inline-block !important;border: none;height: auto;float: none;width: 100%;max-width: 34px;" width="34"/>
                
              </td>
            </tr>
          </table>
          
                </td>
              </tr>
            </tbody>
          </table>
          
          <table style="font-family:arial,helvetica,sans-serif;" role="presentation" cellpadding="0" cellspacing="0" width="100%" border="0">
            <tbody>
              <tr>
                <td class="v-container-padding-padding" style="overflow-wrap:break-word;word-break:break-word;padding:6px 10px 20px;font-family:arial,helvetica,sans-serif;" align="left">
                  
            <div class="v-text-align" style="font-size: 14px; line-height: 140%; text-align: center; word-wrap: break-word;">
              <p style="font-size: 14px; line-height: 140%;"><span style="font-size: 16px; line-height: 22.4px;"><span style="color: #969696; line-height: 22.4px; font-size: 16px;">Invoice No:</span></span></p>
          <p style="font-size: 14px; line-height: 140%;"><span style="font-size: 16px; line-height: 22.4px;"><strong><span style="color: #595959; line-height: 22.4px; font-size: 16px;">#${invoiceNo}</span></strong></span></p>
            </div>
          
                </td>
              </tr>
            </tbody>
          </table>
          
            <!--[if (!mso)&(!IE)]><!--></div><!--<![endif]-->
            </div>
          </div>
          <!--[if (mso)|(IE)]></td><![endif]-->
          <!--[if (mso)|(IE)]><td align="center" width="213" style="width: 213px;padding: 0px;border-top: 0px solid transparent;border-left: 0px solid transparent;border-right: 1px solid #e1e1e1;border-bottom: 0px solid transparent;" valign="top"><![endif]-->
          <div class="u-col u-col-35p67" style="max-width: 320px;min-width: 214.02px;display: table-cell;vertical-align: top;">
            <div style="height: 100%;width: 100% !important;">
            <!--[if (!mso)&(!IE)]><!--><div style="box-sizing: border-box; height: 100%; padding: 0px;border-top: 0px solid transparent;border-left: 0px solid transparent;border-right: 1px solid #e1e1e1;border-bottom: 0px solid transparent;"><!--<![endif]-->
            
          <table style="font-family:arial,helvetica,sans-serif;" role="presentation" cellpadding="0" cellspacing="0" width="100%" border="0">
            <tbody>
              <tr>
                <td class="v-container-padding-padding" style="overflow-wrap:break-word;word-break:break-word;padding:20px 10px 0px;font-family:arial,helvetica,sans-serif;" align="left">
                  
          <table width="100%" cellpadding="0" cellspacing="0" border="0">
            <tr>
              <td class="v-text-align" style="padding-right: 0px;padding-left: 0px;" align="center">
                
                <img align="center" border="0" src="https://i.ibb.co/wsWbQd2/image-7.jpg" alt="Calendar" title="Calendar" style="outline: none;text-decoration: none;-ms-interpolation-mode: bicubic;clear: both;display: inline-block !important;border: none;height: auto;float: none;width: 100%;max-width: 34px;" width="34"/>
                
              </td>
            </tr>
          </table>
          
                </td>
              </tr>
            </tbody>
          </table>
          
          <table style="font-family:arial,helvetica,sans-serif;" role="presentation" cellpadding="0" cellspacing="0" width="100%" border="0">
            <tbody>
              <tr>
                <td class="v-container-padding-padding" style="overflow-wrap:break-word;word-break:break-word;padding:6px 10px 20px;font-family:arial,helvetica,sans-serif;" align="left">
                  
            <div class="v-text-align" style="font-size: 14px; color: #565656; line-height: 140%; text-align: center; word-wrap: break-word;">
              <p style="font-size: 14px; line-height: 140%;"><span style="font-size: 16px; line-height: 22.4px;"><span style="color: #969696; line-height: 22.4px; font-size: 16px;">Invoice Date:</span></span></p>
          <p style="font-size: 14px; line-height: 140%;"><span style="font-size: 16px; line-height: 22.4px;"><strong>${invoiceDate}</strong></span></p>
            </div>
          
                </td>
              </tr>
            </tbody>
          </table>
          
            <!--[if (!mso)&(!IE)]><!--></div><!--<![endif]-->
            </div>
          </div>
          <!--[if (mso)|(IE)]></td><![endif]-->
          <!--[if (mso)|(IE)]><td align="center" width="186" style="width: 186px;padding: 0px;border-top: 0px solid transparent;border-left: 0px solid transparent;border-right: 0px solid transparent;border-bottom: 0px solid transparent;" valign="top"><![endif]-->
          <div class="u-col u-col-31" style="max-width: 320px;min-width: 186px;display: table-cell;vertical-align: top;">
            <div style="height: 100%;width: 100% !important;">
            <!--[if (!mso)&(!IE)]><!--><div style="box-sizing: border-box; height: 100%; padding: 0px;border-top: 0px solid transparent;border-left: 0px solid transparent;border-right: 0px solid transparent;border-bottom: 0px solid transparent;"><!--<![endif]-->
            
          <table style="font-family:arial,helvetica,sans-serif;" role="presentation" cellpadding="0" cellspacing="0" width="100%" border="0">
            <tbody>
              <tr>
                <td class="v-container-padding-padding" style="overflow-wrap:break-word;word-break:break-word;padding:20px 10px 0px;font-family:arial,helvetica,sans-serif;" align="left">
                  
          <table width="100%" cellpadding="0" cellspacing="0" border="0">
            <tr>
              <td class="v-text-align" style="padding-right: 0px;padding-left: 0px;" align="center">
                
                <img align="center" border="0" src="https://i.ibb.co/x5DBpDz/image-5.png" alt="Dollar" title="Dollar" style="outline: none;text-decoration: none;-ms-interpolation-mode: bicubic;clear: both;display: inline-block !important;border: none;height: auto;float: none;width: 100%;max-width: 23px;" width="23"/>
                
              </td>
            </tr>
          </table>
          
                </td>
              </tr>
            </tbody>
          </table>
          
          <table style="font-family:arial,helvetica,sans-serif;" role="presentation" cellpadding="0" cellspacing="0" width="100%" border="0">
            <tbody>
              <tr>
                <td class="v-container-padding-padding" style="overflow-wrap:break-word;word-break:break-word;padding:6px 10px 20px;font-family:arial,helvetica,sans-serif;" align="left">
                  
            <div class="v-text-align" style="font-size: 14px; line-height: 140%; text-align: center; word-wrap: break-word;">
              <p style="font-size: 14px; line-height: 140%;"><span style="font-size: 16px; line-height: 22.4px;"><span style="color: #969696; line-height: 22.4px; font-size: 16px;">Total:</span></span></p>
          <p style="font-size: 14px; line-height: 140%;"><span style="font-size: 16px; line-height: 22.4px;"><span style="font-size: 16px; line-height: 22.4px;"><strong style="color: #595959;">BDT${totalAmount}</strong></span></span></p>
            </div>
          
                </td>
              </tr>
            </tbody>
          </table>
          
            <!--[if (!mso)&(!IE)]><!--></div><!--<![endif]-->
            </div>
          </div>
          <!--[if (mso)|(IE)]></td><![endif]-->
                <!--[if (mso)|(IE)]></tr></table></td></tr></table><![endif]-->
              </div>
            </div>
            </div>
            
            
          <div class="u-row-container" style="padding: 0px;background-color: #eaeaea">
            <div class="u-row" style="margin: 0 auto;min-width: 320px;max-width: 600px;overflow-wrap: break-word;word-wrap: break-word;word-break: break-word;background-color: #ffffff;">
              <div style="border-collapse: collapse;display: table;width: 100%;height: 100%;background-color: transparent;">
                <!--[if (mso)|(IE)]><table width="100%" cellpadding="0" cellspacing="0" border="0"><tr><td style="padding: 0px;background-color: #eaeaea;" align="center"><table cellpadding="0" cellspacing="0" border="0" style="width:600px;"><tr style="background-color: #ffffff;"><![endif]-->
                
          <!--[if (mso)|(IE)]><td align="center" width="600" style="width: 600px;padding: 0px;border-top: 0px solid transparent;border-left: 0px solid transparent;border-right: 0px solid transparent;border-bottom: 0px solid transparent;" valign="top"><![endif]-->
          <div class="u-col u-col-100" style="max-width: 320px;min-width: 600px;display: table-cell;vertical-align: top;">
            <div style="height: 100%;width: 100% !important;">
            <!--[if (!mso)&(!IE)]><!--><div style="box-sizing: border-box; height: 100%; padding: 0px;border-top: 0px solid transparent;border-left: 0px solid transparent;border-right: 0px solid transparent;border-bottom: 0px solid transparent;"><!--<![endif]-->
            
          <table style="font-family:arial,helvetica,sans-serif;" role="presentation" cellpadding="0" cellspacing="0" width="100%" border="0">
            <tbody>
              <tr>
                <td class="v-container-padding-padding" style="overflow-wrap:break-word;word-break:break-word;padding:10px;font-family:arial,helvetica,sans-serif;" align="left">
                  
            <!--[if mso]><table width="100%"><tr><td><![endif]-->
              <h2 class="v-text-align" style="margin: 0px; color: #56b501; line-height: 140%; text-align: center; word-wrap: break-word; font-family: arial,helvetica,sans-serif; font-size: 29px; font-weight: 400;"><strong>Invoice recap</strong></h2>
            <!--[if mso]></td></tr></table><![endif]-->
          
                </td>
              </tr>
            </tbody>
          </table>
          
            <!--[if (!mso)&(!IE)]><!--></div><!--<![endif]-->
            </div>
          </div>
          <!--[if (mso)|(IE)]></td><![endif]-->
                <!--[if (mso)|(IE)]></tr></table></td></tr></table><![endif]-->
              </div>
            </div>
            </div>
            
          
          
            
            
          <div class="u-row-container" style="padding: 0px;background-color: #eaeaea">
            <div class="u-row" style="margin: 0 auto;min-width: 320px;max-width: 600px;overflow-wrap: break-word;word-wrap: break-word;word-break: break-word;background-color: #56b501;">
              <div style="border-collapse: collapse;display: table;width: 100%;height: 100%;background-color: transparent;">
                <!--[if (mso)|(IE)]><table width="100%" cellpadding="0" cellspacing="0" border="0"><tr><td style="padding: 0px;background-color: #eaeaea;" align="center"><table cellpadding="0" cellspacing="0" border="0" style="width:600px;"><tr style="background-color: #56b501;"><![endif]-->
                
          <!--[if (mso)|(IE)]><td align="center" width="199" style="width: 199px;padding: 0px;border-top: 0px solid transparent;border-left: 0px solid transparent;border-right: 1px solid #48a600;border-bottom: 1px solid #48a600;" valign="top"><![endif]-->
          <div class="u-col u-col-33p33" style="max-width: 320px;min-width: 200px;display: table-cell;vertical-align: top;">
            <div style="height: 100%;width: 100% !important;">
            <!--[if (!mso)&(!IE)]><!--><div style="box-sizing: border-box; height: 100%; padding: 0px;border-top: 0px solid transparent;border-left: 0px solid transparent;border-right: 1px solid #48a600;border-bottom: 1px solid #48a600;"><!--<![endif]-->
            
          <table style="font-family:arial,helvetica,sans-serif;" role="presentation" cellpadding="0" cellspacing="0" width="100%" border="0">
            <tbody>
              <tr>
                <td class="v-container-padding-padding" style="overflow-wrap:break-word;word-break:break-word;padding:10px;font-family:arial,helvetica,sans-serif;" align="left">
                  
            <div class="v-text-align" style="font-size: 14px; color: #ffffff; line-height: 140%; text-align: center; word-wrap: break-word;">
              <p style="font-size: 14px; line-height: 140%;"><span style="font-family: georgia, palatino; font-size: 18px; line-height: 25.2px;"><span style="line-height: 25.2px; font-size: 18px;">Service</span></span></p>
            </div>
          
                </td>
              </tr>
            </tbody>
          </table>
          
            <!--[if (!mso)&(!IE)]><!--></div><!--<![endif]-->
            </div>
          </div>
          <!--[if (mso)|(IE)]></td><![endif]-->
          <!--[if (mso)|(IE)]><td align="center" width="199" style="width: 199px;padding: 0px;border-top: 0px solid transparent;border-left: 0px solid transparent;border-right: 1px solid #48a600;border-bottom: 1px solid #48a600;" valign="top"><![endif]-->
          <div class="u-col u-col-33p33" style="max-width: 320px;min-width: 200px;display: table-cell;vertical-align: top;">
            <div style="height: 100%;width: 100% !important;">
            <!--[if (!mso)&(!IE)]><!--><div style="box-sizing: border-box; height: 100%; padding: 0px;border-top: 0px solid transparent;border-left: 0px solid transparent;border-right: 1px solid #48a600;border-bottom: 1px solid #48a600;"><!--<![endif]-->
            
          <table style="font-family:arial,helvetica,sans-serif;" role="presentation" cellpadding="0" cellspacing="0" width="100%" border="0">
            <tbody>
              <tr>
                <td class="v-container-padding-padding" style="overflow-wrap:break-word;word-break:break-word;padding:10px;font-family:arial,helvetica,sans-serif;" align="left">
                  
            <div class="v-text-align" style="font-size: 14px; color: #ffffff; line-height: 140%; text-align: center; word-wrap: break-word;">
              <p style="font-size: 14px; line-height: 140%;"><span style="font-family: georgia, palatino; font-size: 18px; line-height: 25.2px;"><span style="line-height: 25.2px; font-size: 18px;">Quantity</span></span></p>
            </div>
          
                </td>
              </tr>
            </tbody>
          </table>
          
            <!--[if (!mso)&(!IE)]><!--></div><!--<![endif]-->
            </div>
          </div>
          <!--[if (mso)|(IE)]></td><![endif]-->
          <!--[if (mso)|(IE)]><td align="center" width="200" style="width: 200px;padding: 0px;border-top: 0px solid transparent;border-left: 0px solid transparent;border-right: 0px solid transparent;border-bottom: 1px solid #48a600;" valign="top"><![endif]-->
          <div class="u-col u-col-33p33" style="max-width: 320px;min-width: 200px;display: table-cell;vertical-align: top;">
            <div style="height: 100%;width: 100% !important;">
            <!--[if (!mso)&(!IE)]><!--><div style="box-sizing: border-box; height: 100%; padding: 0px;border-top: 0px solid transparent;border-left: 0px solid transparent;border-right: 0px solid transparent;border-bottom: 1px solid #48a600;"><!--<![endif]-->
            
          <table style="font-family:arial,helvetica,sans-serif;" role="presentation" cellpadding="0" cellspacing="0" width="100%" border="0">
            <tbody>
              <tr>
                <td class="v-container-padding-padding" style="overflow-wrap:break-word;word-break:break-word;padding:10px;font-family:arial,helvetica,sans-serif;" align="left">
                  
            <div class="v-text-align" style="font-size: 14px; color: #ffffff; line-height: 140%; text-align: center; word-wrap: break-word;">
              <p style="font-size: 14px; line-height: 140%;"><span style="font-family: georgia, palatino; font-size: 18px; line-height: 25.2px;"><span style="line-height: 25.2px; font-size: 18px;">Total</span></span></p>
            </div>
          
                </td>
              </tr>
            </tbody>
          </table>
          
            <!--[if (!mso)&(!IE)]><!--></div><!--<![endif]-->
            </div>
          </div>
          <!--[if (mso)|(IE)]></td><![endif]-->
                <!--[if (mso)|(IE)]></tr></table></td></tr></table><![endif]-->
              </div>
            </div>
            </div>
            
          
          
            
            
          <div class="u-row-container" style="padding: 0px;background-color: #eaeaea">
            <div class="u-row" style="margin: 0 auto;min-width: 320px;max-width: 600px;overflow-wrap: break-word;word-wrap: break-word;word-break: break-word;background-color: #f5f5f5;">
              <div style="border-collapse: collapse;display: table;width: 100%;height: 100%;background-color: transparent;">
                <!--[if (mso)|(IE)]><table width="100%" cellpadding="0" cellspacing="0" border="0"><tr><td style="padding: 0px;background-color: #eaeaea;" align="center"><table cellpadding="0" cellspacing="0" border="0" style="width:600px;"><tr style="background-color: #f5f5f5;"><![endif]-->
                
          <!--[if (mso)|(IE)]><td align="center" width="199" style="width: 199px;padding: 0px;border-top: 0px solid transparent;border-left: 0px solid transparent;border-right: 1px solid #dfdfdf;border-bottom: 1px solid #dfdfdf;" valign="top"><![endif]-->
          <div class="u-col u-col-33p33" style="max-width: 320px;min-width: 200px;display: table-cell;vertical-align: top;">
            <div style="height: 100%;width: 100% !important;">
            <!--[if (!mso)&(!IE)]><!--><div style="box-sizing: border-box; height: 100%; padding: 0px;border-top: 0px solid transparent;border-left: 0px solid transparent;border-right: 1px solid #dfdfdf;border-bottom: 1px solid #dfdfdf;"><!--<![endif]-->
            
          <table id="u_content_text_14" style="font-family:arial,helvetica,sans-serif;" role="presentation" cellpadding="0" cellspacing="0" width="100%" border="0">
            <tbody>
              <tr>
                <td class="v-container-padding-padding" style="overflow-wrap:break-word;word-break:break-word;padding:10px;font-family:arial,helvetica,sans-serif;" align="left">
                  
            <div class="v-text-align" style="font-size: 14px; color: #b3b3b3; line-height: 140%; text-align: center; word-wrap: break-word;">
              <p style="font-size: 14px; line-height: 140%;" data-sider-select-id="8b24c585-c459-4738-8d41-5f5bcd1472f5">${service}</p>
            </div>
          
                </td>
              </tr>
            </tbody>
          </table>
          
            <!--[if (!mso)&(!IE)]><!--></div><!--<![endif]-->
            </div>
          </div>
          <!--[if (mso)|(IE)]></td><![endif]-->
          <!--[if (mso)|(IE)]><td align="center" width="199" style="width: 199px;padding: 0px;border-top: 0px solid transparent;border-left: 0px solid transparent;border-right: 1px solid #dfdfdf;border-bottom: 1px solid #dfdfdf;" valign="top"><![endif]-->
          <div class="u-col u-col-33p33" style="max-width: 320px;min-width: 200px;display: table-cell;vertical-align: top;">
            <div style="height: 100%;width: 100% !important;">
            <!--[if (!mso)&(!IE)]><!--><div style="box-sizing: border-box; height: 100%; padding: 0px;border-top: 0px solid transparent;border-left: 0px solid transparent;border-right: 1px solid #dfdfdf;border-bottom: 1px solid #dfdfdf;"><!--<![endif]-->
            
          <table id="u_content_text_15" style="font-family:arial,helvetica,sans-serif;" role="presentation" cellpadding="0" cellspacing="0" width="100%" border="0">
            <tbody>
              <tr>
                <td class="v-container-padding-padding" style="overflow-wrap:break-word;word-break:break-word;padding:18px 10px 15px;font-family:arial,helvetica,sans-serif;" align="left">
                  
            <div class="v-text-align" style="font-size: 14px; color: #313131; line-height: 140%; text-align: center; word-wrap: break-word;">
              <p style="font-size: 14px; line-height: 140%;"><span style="font-family: arial, helvetica, sans-serif; font-size: 18px; line-height: 25.2px;"><span style="line-height: 25.2px; font-size: 18px;">${serviceQuantity}</span></span></p>
            </div>
          
                </td>
              </tr>
            </tbody>
          </table>
          
            <!--[if (!mso)&(!IE)]><!--></div><!--<![endif]-->
            </div>
          </div>
          <!--[if (mso)|(IE)]></td><![endif]-->
          <!--[if (mso)|(IE)]><td align="center" width="200" style="width: 200px;padding: 0px;border-top: 0px solid transparent;border-left: 0px solid transparent;border-right: 0px solid transparent;border-bottom: 1px solid #dfdfdf;" valign="top"><![endif]-->
          <div class="u-col u-col-33p33" style="max-width: 320px;min-width: 200px;display: table-cell;vertical-align: top;">
            <div style="height: 100%;width: 100% !important;">
            <!--[if (!mso)&(!IE)]><!--><div style="box-sizing: border-box; height: 100%; padding: 0px;border-top: 0px solid transparent;border-left: 0px solid transparent;border-right: 0px solid transparent;border-bottom: 1px solid #dfdfdf;"><!--<![endif]-->
            
          <table style="font-family:arial,helvetica,sans-serif;" role="presentation" cellpadding="0" cellspacing="0" width="100%" border="0">
            <tbody>
              <tr>
                <td class="v-container-padding-padding" style="overflow-wrap:break-word;word-break:break-word;padding:17px 10px 16px;font-family:arial,helvetica,sans-serif;" align="left">
                  
            <div class="v-text-align" style="font-size: 14px; color: #4b4a4a; line-height: 140%; text-align: center; word-wrap: break-word;">
              <p style="font-size: 14px; line-height: 140%;"><span style="font-family: arial, helvetica, sans-serif; font-size: 18px; line-height: 25.2px;"><span style="line-height: 25.2px; font-size: 18px;" data-sider-select-id="21e95846-be40-4ebd-8329-baaf2717e7e4">BDT ${unitCost}</span></span></p>
            </div>
          
                </td>
              </tr>
            </tbody>
          </table>
          
            <!--[if (!mso)&(!IE)]><!--></div><!--<![endif]-->
            </div>
          </div>
          <!--[if (mso)|(IE)]></td><![endif]-->
                <!--[if (mso)|(IE)]></tr></table></td></tr></table><![endif]-->
              </div>
            </div>
            </div>
            
          
          
            
            
          <div class="u-row-container" style="padding: 0px;background-color: #eaeaea">
            <div class="u-row" style="margin: 0 auto;min-width: 320px;max-width: 600px;overflow-wrap: break-word;word-wrap: break-word;word-break: break-word;background-color: #ffffff;">
              <div style="border-collapse: collapse;display: table;width: 100%;height: 100%;background-color: transparent;">
                <!--[if (mso)|(IE)]><table width="100%" cellpadding="0" cellspacing="0" border="0"><tr><td style="padding: 0px;background-color: #eaeaea;" align="center"><table cellpadding="0" cellspacing="0" border="0" style="width:600px;"><tr style="background-color: #ffffff;"><![endif]-->
                
          <!--[if (mso)|(IE)]><td align="center" width="411" style="width: 411px;padding: 0px;border-top: 0px solid transparent;border-left: 0px solid transparent;border-right: 0px solid transparent;border-bottom: 1px solid #dfdfdf;" valign="top"><![endif]-->
          <div class="u-col u-col-68p5" style="max-width: 320px;min-width: 411px;display: table-cell;vertical-align: top;">
            <div style="height: 100%;width: 100% !important;">
            <!--[if (!mso)&(!IE)]><!--><div style="box-sizing: border-box; height: 100%; padding: 0px;border-top: 0px solid transparent;border-left: 0px solid transparent;border-right: 0px solid transparent;border-bottom: 1px solid #dfdfdf;"><!--<![endif]-->
            
          <table id="u_content_text_26" style="font-family:arial,helvetica,sans-serif;" role="presentation" cellpadding="0" cellspacing="0" width="100%" border="0">
            <tbody>
              <tr>
                <td class="v-container-padding-padding" style="overflow-wrap:break-word;word-break:break-word;padding:10px 10px 12px 15px;font-family:arial,helvetica,sans-serif;" align="left">
                  
            <div class="v-text-align" style="font-size: 14px; color: #408b06; line-height: 140%; text-align: left; word-wrap: break-word;">
              <p style="font-size: 14px; line-height: 140%;"><span style="font-size: 16px; line-height: 22.4px;">Payment method:</span></p>
          <p style="font-size: 14px; line-height: 140%;"><strong><span style="font-size: 16px; line-height: 22.4px;">BKASH</span></strong></p>
            </div>
          
                </td>
              </tr>
            </tbody>
          </table>
          
            <!--[if (!mso)&(!IE)]><!--></div><!--<![endif]-->
            </div>
          </div>
          <!--[if (mso)|(IE)]></td><![endif]-->
          <!--[if (mso)|(IE)]><td align="center" width="189" style="width: 189px;padding: 0px;border-top: 0px solid transparent;border-left: 0px solid transparent;border-right: 0px solid transparent;border-bottom: 1px solid #dfdfdf;" valign="top"><![endif]-->
          <div class="u-col u-col-31p5" style="max-width: 320px;min-width: 189px;display: table-cell;vertical-align: top;">
            <div style="height: 100%;width: 100% !important;">
            <!--[if (!mso)&(!IE)]><!--><div style="box-sizing: border-box; height: 100%; padding: 0px;border-top: 0px solid transparent;border-left: 0px solid transparent;border-right: 0px solid transparent;border-bottom: 1px solid #dfdfdf;"><!--<![endif]-->
            
          <table id="u_content_text_27" style="font-family:arial,helvetica,sans-serif;" role="presentation" cellpadding="0" cellspacing="0" width="100%" border="0">
            <tbody>
              <tr>
                <td class="v-container-padding-padding" style="overflow-wrap:break-word;word-break:break-word;padding:18px 10px 23px 9px;font-family:arial,helvetica,sans-serif;" align="left">
                  
            <div class="v-text-align" style="font-size: 14px; color: #48a600; line-height: 140%; text-align: left; word-wrap: break-word;">
              <p style="font-size: 14px; line-height: 140%;"><span style="font-size: 18px; line-height: 25.2px;"><strong>Total: BDT ${totalAmount}</strong></span></p>
            </div>
          
                </td>
              </tr>
            </tbody>
          </table>
          
            <!--[if (!mso)&(!IE)]><!--></div><!--<![endif]-->
            </div>
          </div>
          <!--[if (mso)|(IE)]></td><![endif]-->
                <!--[if (mso)|(IE)]></tr></table></td></tr></table><![endif]-->
              </div>
            </div>
            </div>
            
          
          
            
            
          <div class="u-row-container" style="padding: 0px;background-color: #eaeaea">
            <div class="u-row" style="margin: 0 auto;min-width: 320px;max-width: 600px;overflow-wrap: break-word;word-wrap: break-word;word-break: break-word;background-color: #ffffff;">
              <div style="border-collapse: collapse;display: table;width: 100%;height: 100%;background-color: transparent;">
                <!--[if (mso)|(IE)]><table width="100%" cellpadding="0" cellspacing="0" border="0"><tr><td style="padding: 0px;background-color: #eaeaea;" align="center"><table cellpadding="0" cellspacing="0" border="0" style="width:600px;"><tr style="background-color: #ffffff;"><![endif]-->
                
          <!--[if (mso)|(IE)]><td align="center" width="600" style="width: 600px;padding: 0px;border-top: 0px solid transparent;border-left: 0px solid transparent;border-right: 0px solid transparent;border-bottom: 0px solid transparent;" valign="top"><![endif]-->
          <div class="u-col u-col-100" style="max-width: 320px;min-width: 600px;display: table-cell;vertical-align: top;">
            <div style="height: 100%;width: 100% !important;">
            <!--[if (!mso)&(!IE)]><!--><div style="box-sizing: border-box; height: 100%; padding: 0px;border-top: 0px solid transparent;border-left: 0px solid transparent;border-right: 0px solid transparent;border-bottom: 0px solid transparent;"><!--<![endif]-->
            
          <table id="u_content_text_28" style="font-family:arial,helvetica,sans-serif;" role="presentation" cellpadding="0" cellspacing="0" width="100%" border="0">
            <tbody>
              <tr>
                <td class="v-container-padding-padding" style="overflow-wrap:break-word;word-break:break-word;padding:40px 10px 0px;font-family:arial,helvetica,sans-serif;" align="left">
                  
            <div class="v-text-align" style="font-size: 14px; color: #48a600; line-height: 140%; text-align: center; word-wrap: break-word;">
              <p style="font-size: 14px; line-height: 140%;"><span style="font-size: 30px; line-height: 42px; font-family: 'Lobster Two', cursive;"><strong>NEED HELP?</strong></span></p>
            </div>
          
                </td>
              </tr>
            </tbody>
          </table>
          
            <!--[if (!mso)&(!IE)]><!--></div><!--<![endif]-->
            </div>
          </div>
          <!--[if (mso)|(IE)]></td><![endif]-->
                <!--[if (mso)|(IE)]></tr></table></td></tr></table><![endif]-->
              </div>
            </div>
            </div>
            
          
          
            
            
          <div class="u-row-container" style="padding: 0px;background-color: #eaeaea">
            <div class="u-row" style="margin: 0 auto;min-width: 320px;max-width: 600px;overflow-wrap: break-word;word-wrap: break-word;word-break: break-word;background-color: #ffffff;">
              <div style="border-collapse: collapse;display: table;width: 100%;height: 100%;background-color: transparent;">
                <!--[if (mso)|(IE)]><table width="100%" cellpadding="0" cellspacing="0" border="0"><tr><td style="padding: 0px;background-color: #eaeaea;" align="center"><table cellpadding="0" cellspacing="0" border="0" style="width:600px;"><tr style="background-color: #ffffff;"><![endif]-->
                
          <!--[if (mso)|(IE)]><td align="center" width="600" style="width: 600px;padding: 0px;border-top: 0px solid transparent;border-left: 0px solid transparent;border-right: 0px solid transparent;border-bottom: 0px solid transparent;" valign="top"><![endif]-->
          <div class="u-col u-col-100" style="max-width: 320px;min-width: 600px;display: table-cell;vertical-align: top;">
            <div style="height: 100%;width: 100% !important;">
            <!--[if (!mso)&(!IE)]><!--><div style="box-sizing: border-box; height: 100%; padding: 0px;border-top: 0px solid transparent;border-left: 0px solid transparent;border-right: 0px solid transparent;border-bottom: 0px solid transparent;"><!--<![endif]-->
            
          <table style="font-family:arial,helvetica,sans-serif;" role="presentation" cellpadding="0" cellspacing="0" width="100%" border="0">
            <tbody>
              <tr>
                <td class="v-container-padding-padding" style="overflow-wrap:break-word;word-break:break-word;padding:10px;font-family:arial,helvetica,sans-serif;" align="left">
                  
            <div class="v-text-align" style="font-size: 14px; color: #858585; line-height: 140%; text-align: left; word-wrap: break-word;">
              <p style="line-height: 140%; text-align: justify;" data-sider-select-id="22879a38-b30e-4c8b-8e61-1eee024c5c65">Your feedback is important to us. Please take a moment to rate and review the service provider once the job is completed. Your insights help us to continually improve our services.</p>
          <p style="line-height: 140%; text-align: justify;">Should you have any questions or require further assistance, feel free to reach out to our support team.</p>
          <p style="line-height: 140%;"> </p>
          <p style="line-height: 140%;" data-sider-select-id="158be848-85e5-46fe-9d91-892545a5485d">Thank you again for choosing Subidha.</p>
          <p style="line-height: 140%;"> </p>
          <p style="line-height: 140%;">Best regards,</p>
          <p style="line-height: 140%;">The Subidha Team</p>
          <p style="line-height: 140%;"><a href="https://www.w3schools.com">Visit Our Website</a></p>
          <p style="line-height: 140%;">jewel15-3817@gmail.com</p>
          <p style="line-height: 140%;">01311929644</p>
            </div>
          
                </td>
              </tr>
            </tbody>
          </table>
          
            <!--[if (!mso)&(!IE)]><!--></div><!--<![endif]-->
            </div>
          </div>
          <!--[if (mso)|(IE)]></td><![endif]-->
                <!--[if (mso)|(IE)]></tr></table></td></tr></table><![endif]-->
              </div>
            </div>
            </div>
            
          
          
            
            
          <div class="u-row-container" style="padding: 25px 0px 20px;background-color: transparent">
            <div class="u-row" style="margin: 0 auto;min-width: 320px;max-width: 600px;overflow-wrap: break-word;word-wrap: break-word;word-break: break-word;background-color: transparent;">
              <div style="border-collapse: collapse;display: table;width: 100%;height: 100%;background-color: transparent;">
                <!--[if (mso)|(IE)]><table width="100%" cellpadding="0" cellspacing="0" border="0"><tr><td style="padding: 25px 0px 20px;background-color: transparent;" align="center"><table cellpadding="0" cellspacing="0" border="0" style="width:600px;"><tr style="background-color: transparent;"><![endif]-->
                
          <!--[if (mso)|(IE)]><td align="center" width="600" style="width: 600px;padding: 0px;border-top: 0px solid transparent;border-left: 0px solid transparent;border-right: 0px solid transparent;border-bottom: 0px solid transparent;" valign="top"><![endif]-->
          <div class="u-col u-col-100" style="max-width: 320px;min-width: 600px;display: table-cell;vertical-align: top;">
            <div style="height: 100%;width: 100% !important;">
            <!--[if (!mso)&(!IE)]><!--><div style="box-sizing: border-box; height: 100%; padding: 0px;border-top: 0px solid transparent;border-left: 0px solid transparent;border-right: 0px solid transparent;border-bottom: 0px solid transparent;"><!--<![endif]-->
            
          <table style="font-family:arial,helvetica,sans-serif;" role="presentation" cellpadding="0" cellspacing="0" width="100%" border="0">
            <tbody>
              <tr>
                <td class="v-container-padding-padding" style="overflow-wrap:break-word;word-break:break-word;padding:10px;font-family:arial,helvetica,sans-serif;" align="left">
                  
          <div align="center">
            <div style="display: table; max-width:167px;">
            <!--[if (mso)|(IE)]><table width="167" cellpadding="0" cellspacing="0" border="0"><tr><td style="border-collapse:collapse;" align="center"><table width="100%" cellpadding="0" cellspacing="0" border="0" style="border-collapse:collapse; mso-table-lspace: 0pt;mso-table-rspace: 0pt; width:167px;"><tr><![endif]-->
            
              
              <!--[if (mso)|(IE)]><td width="32" style="width:32px; padding-right: 10px;" valign="top"><![endif]-->
              <table align="center" border="0" cellspacing="0" cellpadding="0" width="32" height="32" style="width: 32px !important;height: 32px !important;display: inline-block;border-collapse: collapse;table-layout: fixed;border-spacing: 0;mso-table-lspace: 0pt;mso-table-rspace: 0pt;vertical-align: top;margin-right: 10px">
                <tbody><tr style="vertical-align: top"><td align="center" valign="middle" style="word-break: break-word;border-collapse: collapse !important;vertical-align: top">
                  <a href="https://facebook.com/" title="Facebook" target="_blank">
                    <img src="https://i.ibb.co/cK56y6q/image-3.png" alt="Facebook" title="Facebook" width="32" style="outline: none;text-decoration: none;-ms-interpolation-mode: bicubic;clear: both;display: block !important;border: none;height: auto;float: none;max-width: 32px !important">
                  </a>
                </td></tr>
              </tbody></table>
              <!--[if (mso)|(IE)]></td><![endif]-->
              
              <!--[if (mso)|(IE)]><td width="32" style="width:32px; padding-right: 10px;" valign="top"><![endif]-->
              <table align="center" border="0" cellspacing="0" cellpadding="0" width="32" height="32" style="width: 32px !important;height: 32px !important;display: inline-block;border-collapse: collapse;table-layout: fixed;border-spacing: 0;mso-table-lspace: 0pt;mso-table-rspace: 0pt;vertical-align: top;margin-right: 10px">
                <tbody><tr style="vertical-align: top"><td align="center" valign="middle" style="word-break: break-word;border-collapse: collapse !important;vertical-align: top">
                  <a href="https://twitter.com/" title="Twitter" target="_blank">
                    <img src="https://i.ibb.co/pyT9ZCP/image-2.png" alt="Twitter" title="Twitter" width="32" style="outline: none;text-decoration: none;-ms-interpolation-mode: bicubic;clear: both;display: block !important;border: none;height: auto;float: none;max-width: 32px !important">
                  </a>
                </td></tr>
              </tbody></table>
              <!--[if (mso)|(IE)]></td><![endif]-->
              
              <!--[if (mso)|(IE)]><td width="32" style="width:32px; padding-right: 10px;" valign="top"><![endif]-->
              <table align="center" border="0" cellspacing="0" cellpadding="0" width="32" height="32" style="width: 32px !important;height: 32px !important;display: inline-block;border-collapse: collapse;table-layout: fixed;border-spacing: 0;mso-table-lspace: 0pt;mso-table-rspace: 0pt;vertical-align: top;margin-right: 10px">
                <tbody><tr style="vertical-align: top"><td align="center" valign="middle" style="word-break: break-word;border-collapse: collapse !important;vertical-align: top">
                  <a href="https://instagram.com/" title="Instagram" target="_blank">
                    <img src="https://i.ibb.co/v482XhK/image-4.png" alt="Instagram" title="Instagram" width="32" style="outline: none;text-decoration: none;-ms-interpolation-mode: bicubic;clear: both;display: block !important;border: none;height: auto;float: none;max-width: 32px !important">
                  </a>
                </td></tr>
              </tbody></table>
              <!--[if (mso)|(IE)]></td><![endif]-->
              
              <!--[if (mso)|(IE)]><td width="32" style="width:32px; padding-right: 0px;" valign="top"><![endif]-->
              <table align="center" border="0" cellspacing="0" cellpadding="0" width="32" height="32" style="width: 32px !important;height: 32px !important;display: inline-block;border-collapse: collapse;table-layout: fixed;border-spacing: 0;mso-table-lspace: 0pt;mso-table-rspace: 0pt;vertical-align: top;margin-right: 0px">
                <tbody><tr style="vertical-align: top"><td align="center" valign="middle" style="word-break: break-word;border-collapse: collapse !important;vertical-align: top">
                  <a href="https://linkedin.com/" title="LinkedIn" target="_blank">
                    <img src="https://i.ibb.co/vkH806c/image-1.png" alt="LinkedIn" title="LinkedIn" width="32" style="outline: none;text-decoration: none;-ms-interpolation-mode: bicubic;clear: both;display: block !important;border: none;height: auto;float: none;max-width: 32px !important">
                  </a>
                </td></tr>
              </tbody></table>
              <!--[if (mso)|(IE)]></td><![endif]-->
              
              
              <!--[if (mso)|(IE)]></tr></table></td></tr></table><![endif]-->
            </div>
          </div>
          
                </td>
              </tr>
            </tbody>
          </table>
          
            <!--[if (!mso)&(!IE)]><!--></div><!--<![endif]-->
            </div>
          </div>
          <!--[if (mso)|(IE)]></td><![endif]-->
                <!--[if (mso)|(IE)]></tr></table></td></tr></table><![endif]-->
              </div>
            </div>
            </div>
            
          
          
            
            
          <div class="u-row-container" style="padding: 0px;background-color: transparent">
            <div class="u-row" style="margin: 0 auto;min-width: 320px;max-width: 600px;overflow-wrap: break-word;word-wrap: break-word;word-break: break-word;background-color: transparent;">
              <div style="border-collapse: collapse;display: table;width: 100%;height: 100%;background-color: transparent;">
                <!--[if (mso)|(IE)]><table width="100%" cellpadding="0" cellspacing="0" border="0"><tr><td style="padding: 0px;background-color: transparent;" align="center"><table cellpadding="0" cellspacing="0" border="0" style="width:600px;"><tr style="background-color: transparent;"><![endif]-->
                
          <!--[if (mso)|(IE)]><td align="center" width="600" style="width: 600px;padding: 0px;border-top: 0px solid transparent;border-left: 0px solid transparent;border-right: 0px solid transparent;border-bottom: 0px solid transparent;" valign="top"><![endif]-->
          <div class="u-col u-col-100" style="max-width: 320px;min-width: 600px;display: table-cell;vertical-align: top;">
            <div style="height: 100%;width: 100% !important;">
            <!--[if (!mso)&(!IE)]><!--><div style="box-sizing: border-box; height: 100%; padding: 0px;border-top: 0px solid transparent;border-left: 0px solid transparent;border-right: 0px solid transparent;border-bottom: 0px solid transparent;"><!--<![endif]-->
            
          <table style="font-family:arial,helvetica,sans-serif;" role="presentation" cellpadding="0" cellspacing="0" width="100%" border="0">
            <tbody>
              <tr>
                <td class="v-container-padding-padding" style="overflow-wrap:break-word;word-break:break-word;padding:15px 10px;font-family:arial,helvetica,sans-serif;" align="left">
                  
            <div class="v-text-align" style="font-size: 14px; color: #646464; line-height: 140%; text-align: center; word-wrap: break-word;">
              <p style="font-size: 14px; line-height: 140%;" data-sider-select-id="9a0d1072-7a6e-4a53-99af-40ba269638a9">All rights reserved. Subidha Home Service</p>
            </div>
          
                </td>
              </tr>
            </tbody>
          </table>
          
            <!--[if (!mso)&(!IE)]><!--></div><!--<![endif]-->
            </div>
          </div>
          <!--[if (mso)|(IE)]></td><![endif]-->
                <!--[if (mso)|(IE)]></tr></table></td></tr></table><![endif]-->
              </div>
            </div>
            </div>
            
          
          
              <!--[if (mso)|(IE)]></td></tr></table><![endif]-->
              </td>
            </tr>
            </tbody>
            </table>
            <!--[if mso]></div><![endif]-->
            <!--[if IE]></div><![endif]-->
          </body>
          
          </html>
          
          `,
        };
        transporter.sendMail(mail_configs, function (error, info) {
          if (error) {
            console.log(error);
            return reject({ message: `An error has occurred` });
          }
          return resolve({ message: "Email sent successfully" });
        });
      });
    }

    // GET endpoint to fetch user data by UID
    app.get("/api/user/:uid", async (req, res) => {
      try {
        const uid = req.params.uid;
        const user = await usersCollection.findOne({ uid });

        if (!user) {
          return res.status(404).json({ error: "User not found" });
        }

        // Use placeholder image if photoURL is missing or empty
        const placeholderImage =
          "https://via.placeholder.com/150x150/cccccc/666666?text=User";
        const userImage =
          user.photoURL && user.photoURL.trim() !== ""
            ? user.photoURL
            : placeholderImage;

        res.json({
          uid: user.uid,
          name: user.name,
          email: user.email,
          phone: user.phone,
          role: user.role,
          isVerified: user.isVerified,
          status: user.status,
          photoURL: userImage,
        });
      } catch (error) {
        console.error("Error fetching user:", error);
        res.status(500).json({ error: "Internal server error" });
      }
    });

    app.post("/staff", async (req, res) => {
      const staff = req.body;
      try {
        const result = await staffCollection.insertOne(staff);
        res.send(result);
      } catch (error) {
        res.status(500).json({ error: "Internal server error" });
      }
    });

    app.get("/staff/:providerId", async (req, res) => {
      const providerId = req.params.providerId;
      try {
        const query = {
          providerId,
        };
        const staffs = await staffCollection.find(query).toArray();
        res.send(staffs);
      } catch (error) {
        res.status(500).json({ error: "Internal server error" });
      }
    });

    app.get("/messages/:uid", async (req, res) => {
      try {
        const uid = req.params.uid;
        const query = {
          $or: [{ senderId: uid }, { receiverId: uid }],
        };
        const conversations = await messageCollection.find(query).toArray();

        const previousMessagesData = await Promise.all(
          conversations.map(async (conversation) => {
            const conversationIDs = conversation.roomId.split("-");
            const receiverId =
              conversationIDs[0] === uid
                ? conversationIDs[1]
                : conversationIDs[0];
            const user = await usersCollection.findOne({ uid: receiverId });
            const lastMessage =
              conversation.messages[conversation.messages.length - 1];

            let formattedLastMessage;
            if (lastMessage.senderId === uid) {
              formattedLastMessage = `You: ${lastMessage.message}`;
            } else {
              formattedLastMessage = lastMessage.message;
            }

            // Use placeholder image if photoURL is missing or empty
            const placeholderImage =
              "https://via.placeholder.com/150x150/cccccc/666666?text=User";
            const userImage =
              user.photoURL && user.photoURL.trim() !== ""
                ? user.photoURL
                : placeholderImage;

            return {
              uid: user.uid,
              userName: user.userName,
              photoURL: userImage,
              lastMessage: formattedLastMessage,
            };
          })
        );

        res.send(previousMessagesData);
      } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Internal Server Error" });
      }
    });

    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );

    // Get service provider statistics (Admin only)
    app.get("/api/service-providers/stats", async (req, res) => {
      try {
        const totalProviders = await providersCollection.countDocuments();
        const pendingProviders = await providersCollection.countDocuments({
          status: "pending",
        });
        const approvedProviders = await providersCollection.countDocuments({
          status: "approved",
        });
        const rejectedProviders = await providersCollection.countDocuments({
          status: "rejected",
        });
        const suspendedProviders = await providersCollection.countDocuments({
          status: "suspended",
        });

        // Get recent registrations (last 30 days)
        const thirtyDaysAgo = new Date();
        thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

        const recentRegistrations = await providersCollection.countDocuments({
          registrationDate: { $gte: thirtyDaysAgo },
        });

        // Get category distribution
        const categoryStats = await providersCollection
          .aggregate([
            { $unwind: "$serviceCategories" },
            { $group: { _id: "$serviceCategories", count: { $sum: 1 } } },
            { $sort: { count: -1 } },
            { $limit: 10 },
          ])
          .toArray();

        res.json({
          success: true,
          data: {
            total: totalProviders,
            pending: pendingProviders,
            approved: approvedProviders,
            rejected: rejectedProviders,
            suspended: suspendedProviders,
            recentRegistrations: recentRegistrations,
            categoryDistribution: categoryStats,
          },
        });
      } catch (error) {
        console.error("Error fetching service provider stats:", error);
        res.status(500).json({
          success: false,
          error: "Internal Server Error",
          message: "Failed to fetch service provider statistics",
        });
      }
    });
  } catch (error) {
    console.error("❌ MongoDB connection error:", error);
    process.exit(1);
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);

// Service creation endpoint
app.post("/services", async (req, res) => {
  const servicesCollection = client
    .db("SubidhaHomeService")
    .collection("services");

  try {
    const serviceData = req.body;

    // Validate required fields
    if (!serviceData.serviceName || !serviceData.description) {
      return res.status(400).json({
        error: "Service name and description are required",
      });
    }

    // Add timestamp
    serviceData.createdAt = new Date();
    serviceData.updatedAt = new Date();

    // Insert service into database
    const result = await servicesCollection.insertOne(serviceData);

    res.status(201).json({
      message: "Service created successfully",
      serviceId: result.insertedId,
    });
  } catch (error) {
    console.error("Error creating service:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Get all services - Admin endpoint
app.get("/admin-services", async (req, res) => {
  const servicesCollection = client
    .db("SubidhaHomeService")
    .collection("services");
  try {
    const services = await servicesCollection.find().toArray();
    res.json(services);
  } catch (error) {
    console.error("Error fetching services:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Delete user account (Firebase + Database)
app.delete("/users/:id", async (req, res) => {
  try {
    const id = req.params.id;

    // First check if user exists in database by _id
    const user = await usersCollection.findOne({ _id: new ObjectId(id) });

    if (!user) {
      return res.status(404).json({
        error: "User not found",
        success: false,
      });
    }

    // Delete user from database by _id
    const dbResult = await usersCollection.deleteOne({ _id: new ObjectId(id) });

    if (dbResult.deletedCount === 0) {
      return res.status(500).json({
        error: "Failed to delete user from database",
        success: false,
      });
    }

    // Note: Firebase user deletion should be handled on frontend
    // as it requires admin SDK or user authentication
    res.json({
      message: "User deleted successfully from database",
      success: true,
      deletedCount: dbResult.deletedCount,
      uid: uid,
    });
  } catch (error) {
    console.error("Error deleting user:", error);
    res.status(500).json({
      error: "Internal server error",
      success: false,
    });
  }
});

// Check user status for login
app.get("/check-user-status/:uid", async (req, res) => {
  try {
    const uid = req.params.uid;
    const user = await usersCollection.findOne({ uid });

    if (!user) {
      return res.status(404).json({
        error: "User not found",
        canLogin: false,
      });
    }

    // Check if user is active
    if (user.status === "Inactive") {
      return res.status(403).json({
        error: "Your account has been deactivated. Please contact support.",
        canLogin: false,
        status: user.status,
      });
    }

    if (user.status === "Pending") {
      return res.status(403).json({
        error:
          "Your account is pending approval. Please wait for admin approval.",
        canLogin: false,
        status: user.status,
      });
    }

    // User is active
    // Use placeholder image if photoURL is missing or empty
    const placeholderImage =
      "https://via.placeholder.com/150x150/cccccc/666666?text=User";
    const userImage =
      user.photoURL && user.photoURL.trim() !== ""
        ? user.photoURL
        : placeholderImage;

    res.json({
      canLogin: true,
      status: user.status,
      user: {
        uid: user.uid,
        userName: user.userName,
        email: user.email,
        role: user.role,
        status: user.status,
        photoURL: userImage,
      },
    });
  } catch (error) {
    console.error("Error checking user status:", error);
    res.status(500).json({
      error: "Internal server error",
      canLogin: false,
    });
  }
});

// ==================== ROLES & PERMISSIONS API ENDPOINTS ====================

// GET all roles
app.get("/roles", async (req, res) => {
  try {
    const roles = await rolesCollection.find({}).toArray();
    res.json(roles);
  } catch (error) {
    console.error("Error fetching roles:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// GET single role by ID
app.get("/roles/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const role = await rolesCollection.findOne({ _id: new ObjectId(id) });

    if (!role) {
      return res.status(404).json({ error: "Role not found" });
    }

    res.json(role);
  } catch (error) {
    console.error("Error fetching role:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// POST create new role
app.post("/roles", async (req, res) => {
  try {
    const { roleName, permissions, description } = req.body;

    // Validation
    if (!roleName || !permissions || !Array.isArray(permissions)) {
      return res.status(400).json({
        error: "Role name and permissions array are required",
      });
    }

    // Check if role already exists
    const existingRole = await rolesCollection.findOne({
      roleName: { $regex: new RegExp(`^${roleName}$`, "i") },
    });

    if (existingRole) {
      return res.status(409).json({
        error: "Role with this name already exists",
      });
    }

    const newRole = {
      roleName,
      permissions,
      description: description || "",
      createdAt: new Date(),
      updatedAt: new Date(),
      isActive: true,
      userCount: 0,
    };

    const result = await rolesCollection.insertOne(newRole);

    res.status(201).json({
      message: "Role created successfully",
      role: { _id: result.insertedId, ...newRole },
    });
  } catch (error) {
    console.error("Error creating role:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// PUT update role
app.put("/roles/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const { roleName, permissions, description, isActive } = req.body;

    // Validation
    if (!roleName || !permissions || !Array.isArray(permissions)) {
      return res.status(400).json({
        error: "Role name and permissions array are required",
      });
    }

    // Check if role exists
    const existingRole = await rolesCollection.findOne({
      _id: new ObjectId(id),
    });
    if (!existingRole) {
      return res.status(404).json({ error: "Role not found" });
    }

    // Check if another role with same name exists (excluding current role)
    const duplicateRole = await rolesCollection.findOne({
      roleName: { $regex: new RegExp(`^${roleName}$`, "i") },
      _id: { $ne: new ObjectId(id) },
    });

    if (duplicateRole) {
      return res.status(409).json({
        error: "Role with this name already exists",
      });
    }

    const updatedRole = {
      roleName,
      permissions,
      description: description || existingRole.description,
      isActive: isActive !== undefined ? isActive : existingRole.isActive,
      updatedAt: new Date(),
      createdAt: existingRole.createdAt,
      userCount: existingRole.userCount,
    };

    const result = await rolesCollection.findOneAndUpdate(
      { _id: new ObjectId(id) },
      { $set: updatedRole },
      { returnOriginal: false }
    );

    res.json({
      message: "Role updated successfully",
      role: result.value,
    });
  } catch (error) {
    console.error("Error updating role:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// DELETE role
app.delete("/roles/:id", async (req, res) => {
  try {
    const { id } = req.params;

    // Check if role exists
    const existingRole = await rolesCollection.findOne({
      _id: new ObjectId(id),
    });
    if (!existingRole) {
      return res.status(404).json({ error: "Role not found" });
    }

    // Check if any users are assigned to this role
    const usersWithRole = await usersCollection.countDocuments({
      role: existingRole.roleName,
    });
    if (usersWithRole > 0) {
      return res.status(409).json({
        error: `Cannot delete role. ${usersWithRole} user(s) are assigned to this role. Please reassign users first.`,
      });
    }

    await rolesCollection.deleteOne({ _id: new ObjectId(id) });

    res.json({ message: "Role deleted successfully" });
  } catch (error) {
    console.error("Error deleting role:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// GET role statistics
app.get("/roles/statistics", async (req, res) => {
  try {
    const totalRoles = await rolesCollection.countDocuments({});
    const activeRoles = await rolesCollection.countDocuments({
      isActive: true,
    });
    const inactiveRoles = await rolesCollection.countDocuments({
      isActive: false,
    });

    // Get role usage statistics
    const roleUsage = await rolesCollection
      .aggregate([
        {
          $lookup: {
            from: "users",
            localField: "roleName",
            foreignField: "role",
            as: "users",
          },
        },
        {
          $project: {
            roleName: 1,
            userCount: { $size: "$users" },
            isActive: 1,
          },
        },
        {
          $sort: { userCount: -1 },
        },
      ])
      .toArray();

    res.json({
      totalRoles,
      activeRoles,
      inactiveRoles,
      roleUsage,
    });
  } catch (error) {
    console.error("Error fetching role statistics:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// GET available permissions
app.get("/permissions", async (req, res) => {
  try {
    const permissions = [
      // Dashboard
      {
        category: "Dashboard",
        permissions: ["view_dashboard", "view_analytics", "view_reports"],
      },

      // User Management
      {
        category: "User Management",
        permissions: [
          "view_users",
          "create_users",
          "edit_users",
          "delete_users",
          "manage_user_roles",
        ],
      },

      // Service Provider Management
      {
        category: "Service Provider Management",
        permissions: [
          "view_providers",
          "approve_providers",
          "suspend_providers",
          "delete_providers",
          "view_provider_details",
        ],
      },

      // Service Management
      {
        category: "Service Management",
        permissions: [
          "view_services",
          "create_services",
          "edit_services",
          "delete_services",
          "manage_categories",
          "manage_subcategories",
        ],
      },

      // Booking Management
      {
        category: "Booking Management",
        permissions: [
          "view_bookings",
          "manage_bookings",
          "cancel_bookings",
          "view_booking_details",
          "process_refunds",
        ],
      },

      // Financial Management
      {
        category: "Financial Management",
        permissions: [
          "view_revenue",
          "view_payments",
          "manage_payments",
          "view_financial_reports",
          "manage_commissions",
        ],
      },

      // Content Management
      {
        category: "Content Management",
        permissions: [
          "manage_offers",
          "manage_coupons",
          "manage_announcements",
          "manage_faqs",
        ],
      },

      // Communication
      {
        category: "Communication",
        permissions: ["view_messages", "send_messages", "send_notifications"],
      },

      // System Administration
      {
        category: "System Administration",
        permissions: [
          "manage_roles",
          "manage_permissions",
          "view_system_logs",
          "manage_settings",
          "backup_data",
        ],
      },

      // Staff Management
      {
        category: "Staff Management",
        permissions: [
          "view_staff",
          "create_staff",
          "edit_staff",
          "delete_staff",
          "manage_staff_schedules",
        ],
      },

      // Reviews & Ratings
      {
        category: "Reviews & Ratings",
        permissions: [
          "view_reviews",
          "moderate_reviews",
          "delete_reviews",
          "manage_rating_types",
        ],
      },
    ];

    res.json(permissions);
  } catch (error) {
    console.error("Error fetching permissions:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// Assign role to user
app.put("/users/:userId/role", async (req, res) => {
  try {
    const { userId } = req.params;
    const { roleName } = req.body;

    if (!roleName) {
      return res.status(400).json({ error: "Role name is required" });
    }

    // Check if role exists
    const role = await rolesCollection.findOne({ roleName, isActive: true });
    if (!role) {
      return res.status(404).json({ error: "Role not found or inactive" });
    }

    // Update user role
    const result = await usersCollection.findOneAndUpdate(
      { _id: new ObjectId(userId) },
      { $set: { role: roleName, updatedAt: new Date() } },
      { returnOriginal: false }
    );

    if (!result.value) {
      return res.status(404).json({ error: "User not found" });
    }

    // Update role user count
    await rolesCollection.updateOne({ roleName }, { $inc: { userCount: 1 } });

    res.json({
      message: "User role updated successfully",
      user: result.value,
    });
  } catch (error) {
    console.error("Error assigning role to user:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// ==================== SERVICES API ENDPOINTS ====================

// GET all services - basic version
app.get("/services", async (req, res) => {
  const servicesCollection = client
    .db("SubidhaHomeService")
    .collection("services");
  try {
    // Get all services
    const services = await servicesCollection.find({}).toArray();

    // Get total count
    const totalServices = services.length;

    // Simple pagination
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;

    const paginatedServices = services.slice(skip, skip + limit);
    const totalPages = Math.ceil(totalServices / limit);

    res.json({
      services: paginatedServices,
      pagination: {
        currentPage: page,
        totalPages,
        totalServices,
        limit: limit,
        hasNextPage: page < totalPages,
        hasPreviousPage: page > 1,
      },
    });
  } catch (error) {
    console.error("Error fetching services:", error);
    res
      .status(500)
      .json({ error: "Internal Server Error", details: error.message });
  }
});

// GET service statistics
app.get("/services/statistics", async (req, res) => {
  const servicesCollection = client
    .db("SubidhaHomeService")
    .collection("services");
  try {
    const totalServices = await servicesCollection.countDocuments();

    const activeServices = await servicesCollection.countDocuments({
      status: "active",
    });

    const featuredServices = await servicesCollection.countDocuments({
      isFeatured: true,
    });

    // Get recent services (last 30 days)
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

    const recentServices = await servicesCollection.countDocuments({
      createdAt: { $gte: thirtyDaysAgo },
    });

    // Get total revenue
    const services = await servicesCollection.find({}).toArray();
    const totalRevenue = services.reduce(
      (sum, service) => sum + (service.price || 0),
      0
    );

    // Get service growth over time (last 6 months)
    const sixMonthsAgo = new Date();
    sixMonthsAgo.setMonth(sixMonthsAgo.getMonth() - 6);

    const serviceGrowth = await servicesCollection
      .aggregate([
        {
          $match: {
            createdAt: { $gte: sixMonthsAgo },
          },
        },
        {
          $group: {
            _id: {
              year: { $year: "$createdAt" },
              month: { $month: "$createdAt" },
            },
            count: { $sum: 1 },
          },
        },
        {
          $sort: { "_id.year": 1, "_id.month": 1 },
        },
      ])
      .toArray();

    res.json({
      totalServices,
      activeServices,
      featuredServices,
      recentServices,
      totalRevenue,
      serviceGrowth,
    });
  } catch (error) {
    console.error("Error fetching service statistics:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// POST create new service
app.post("/services", async (req, res) => {
  try {
    const {
      serviceName,
      description,
      price,
      duration,
      category,
      icon,
      status = "active",
      isFeatured = false,
    } = req.body;

    // Validate required fields
    if (!serviceName || !description || !category) {
      return res.status(400).json({
        error: "Service name, description, and category are required",
      });
    }

    const newService = {
      serviceName,
      description,
      price: price ? parseFloat(price) : 0,
      duration: duration ? parseInt(duration) : null,
      category,
      icon: icon || null,
      status,
      isFeatured: Boolean(isFeatured),
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };

    const result = await servicesCollection.insertOne(newService);

    if (result.insertedId) {
      // Update category service count
      await categoriesCollection.updateOne(
        { _id: new ObjectId(category) },
        { $inc: { totalService: 1 } }
      );

      res.status(201).json({
        _id: result.insertedId,
        ...newService,
      });
    } else {
      res.status(500).json({ error: "Failed to create service" });
    }
  } catch (error) {
    console.error("Error creating service:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// PUT update service
app.put("/services/:id", async (req, res) => {
  try {
    const serviceId = req.params.id;
    const updateData = req.body;

    // Remove _id from update data
    delete updateData._id;

    updateData.updatedAt = new Date().toISOString();

    const result = await servicesCollection.updateOne(
      { _id: new ObjectId(serviceId) },
      { $set: updateData }
    );

    if (result.matchedCount === 0) {
      return res.status(404).json({ error: "Service not found" });
    }

    if (result.modifiedCount > 0) {
      res.json({ message: "Service updated successfully" });
    } else {
      res.json({ message: "No changes made to service" });
    }
  } catch (error) {
    console.error("Error updating service:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// DELETE service
app.delete("/delete-service/:id", verifyAdmin, async (req, res) => {
  const servicesCollection = client
    .db("SubidhaHomeService")
    .collection("services");
  const categoriesCollection = client
    .db("SubidhaHomeService")
    .collection("categories");

  try {
    const serviceId = req.params.id;

    // Get service details before deletion
    const service = await servicesCollection.findOne({
      _id: new ObjectId(serviceId),
    });

    if (!service) {
      return res.status(404).json({ error: "Service not found" });
    }

    const result = await servicesCollection.deleteOne({
      _id: new ObjectId(serviceId),
    });

    if (result.deletedCount > 0) {
      // Update category service count
      if (service.category) {
        await categoriesCollection.updateOne(
          { _id: new ObjectId(service.category) },
          { $inc: { totalService: -1 } }
        );
      }

      res.json({ message: "Service deleted successfully" });
    } else {
      res.status(500).json({ error: "Failed to delete service" });
    }
  } catch (error) {
    console.error("Error deleting service:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// Endpoint to delete ALL services
app.delete("/delete-all-services", async (req, res) => {
  try {
    console.log("Deleting all services...");

    // Get count before deletion
    const countBefore = await servicesCollection.countDocuments();

    // Get all services to update category counts
    const services = await servicesCollection.find({}).toArray();

    // Delete all services
    const result = await servicesCollection.deleteMany({});

    // Update category service counts
    const categoryUpdates = {};
    services.forEach((service) => {
      if (service.category) {
        const categoryId = service.category.toString();
        categoryUpdates[categoryId] = (categoryUpdates[categoryId] || 0) + 1;
      }
    });

    // Update each category's service count
    for (const [categoryId, count] of Object.entries(categoryUpdates)) {
      await categoriesCollection.updateOne(
        { _id: new ObjectId(categoryId) },
        { $inc: { totalService: -count } }
      );
    }

    console.log(
      `Deleted ${result.deletedCount} services out of ${countBefore} total`
    );

    res.status(200).json({
      message: "All services deleted successfully",
      deletedCount: result.deletedCount,
      totalCount: countBefore,
      updatedCategories: Object.keys(categoryUpdates).length,
    });
  } catch (error) {
    console.error("Error deleting all services:", error);
    res.status(500).json({ error: "Failed to delete all services" });
  }
});

// Endpoint to get services by category ID
app.get("/services/by-category/:categoryId", async (req, res) => {
  const servicesCollection = client
    .db("SubidhaHomeService")
    .collection("services");
  const categoriesCollection = client
    .db("SubidhaHomeService")
    .collection("categories");

  try {
    const categoryId = req.params.categoryId;
    console.log("Fetching services for category:", categoryId);

    // Validate category ID format
    if (!ObjectId.isValid(categoryId)) {
      return res.status(400).json({ error: "Invalid category ID format" });
    }

    // Check if category exists
    const category = await categoriesCollection.findOne({
      _id: new ObjectId(categoryId),
    });

    if (!category) {
      return res.status(404).json({ error: "Category not found" });
    }

    // Get services for this category (category field is stored as string)
    const services = await servicesCollection
      .find({ category: categoryId })
      .toArray();

    // Get total count for pagination info
    const totalCount = await servicesCollection.countDocuments({
      category: categoryId,
    });

    console.log(`Found ${services.length} services for category ${categoryId}`);

    res.status(200).json({
      message: "Services fetched successfully",
      category: {
        _id: category._id,
        serviceName: category.serviceName,
        description: category.description,
      },
      services: services,
      totalCount: totalCount,
      count: services.length,
    });
  } catch (error) {
    console.error("Error fetching services by category:", error);
    res.status(500).json({ error: "Failed to fetch services by category" });
  }
});

app.get("/", (req, res) => {
  res.send("Subidha Home Service Server is Running...");
});

// Test endpoint
app.get("/test-services", async (req, res) => {
  try {
    const servicesCollection = client
      .db("SubidhaHomeService")
      .collection("services");
    const count = await servicesCollection.countDocuments();
    res.json({ message: "Services collection accessible", count });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ==================== SERVICES API ENDPOINTS ====================

// GET all services with pagination, search, and filtering
app.get("/services", async (req, res) => {
  try {
    console.log("Services endpoint called");
    const servicesCollection = client
      .db("SubidhaHomeService")
      .collection("services");
    console.log("Collection accessed");
    const {
      page = 1,
      limit = 10,
      search = "",
      category = "",
      status = "",
      sortBy = "createdAt",
      sortOrder = "desc",
    } = req.query;

    // Build query object
    let query = {};
    let andConditions = [];

    // Search filter
    if (search) {
      andConditions.push({
        $or: [
          { serviceName: { $regex: search, $options: "i" } },
          { description: { $regex: search, $options: "i" } },
        ],
      });
    }

    // Category filter
    if (category) {
      console.log("=== CATEGORY FILTER DEBUG ===");
      console.log("Category ID received:", category);
      console.log("Category type:", typeof category);

      try {
        const objectId = new ObjectId(category);
        andConditions.push({ category: objectId });
        console.log("Using ObjectId filter:", objectId);
      } catch (error) {
        console.log("ObjectId conversion failed, using string:", error.message);
        andConditions.push({ category: category });
      }

      console.log("=== END CATEGORY FILTER DEBUG ===");
    }

    // Status filter
    if (status) {
      andConditions.push({ status: status });
    }

    // Combine all conditions
    if (andConditions.length > 0) {
      query.$and = andConditions;
    }

    console.log("Final query:", JSON.stringify(query, null, 2));

    // Build sort object
    const sort = {};
    sort[sortBy] = sortOrder === "desc" ? -1 : 1;

    // Calculate pagination
    const skip = (parseInt(page) - 1) * parseInt(limit);

    // Get total count
    const totalServices = await servicesCollection.countDocuments(query);

    // Fetch services with pagination and sorting
    const services = await servicesCollection
      .find(query)
      .sort(sort)
      .skip(skip)
      .limit(parseInt(limit))
      .toArray();

    // Calculate pagination info
    const totalPages = Math.ceil(totalServices / parseInt(limit));

    res.json({
      services,
      pagination: {
        currentPage: parseInt(page),
        totalPages,
        totalServices,
        limit: parseInt(limit),
        hasNextPage: parseInt(page) < totalPages,
        hasPreviousPage: parseInt(page) > 1,
      },
    });
  } catch (error) {
    console.error("Error fetching services:", error);
    res
      .status(500)
      .json({ error: "Internal Server Error", details: error.message });
  }
});

// GET service statistics
app.get("/services/statistics", async (req, res) => {
  const servicesCollection = client
    .db("SubidhaHomeService")
    .collection("services");
  try {
    const totalServices = await servicesCollection.countDocuments();

    const activeServices = await servicesCollection.countDocuments({
      status: "active",
    });

    const featuredServices = await servicesCollection.countDocuments({
      isFeatured: true,
    });

    // Get recent services (last 30 days)
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

    const recentServices = await servicesCollection.countDocuments({
      createdAt: { $gte: thirtyDaysAgo },
    });

    // Get total revenue
    const services = await servicesCollection.find({}).toArray();
    const totalRevenue = services.reduce(
      (sum, service) => sum + (service.price || 0),
      0
    );

    // Get service growth over time (last 6 months)
    const sixMonthsAgo = new Date();
    sixMonthsAgo.setMonth(sixMonthsAgo.getMonth() - 6);

    const serviceGrowth = await servicesCollection
      .aggregate([
        {
          $match: {
            createdAt: { $gte: sixMonthsAgo },
          },
        },
        {
          $group: {
            _id: {
              year: { $year: "$createdAt" },
              month: { $month: "$createdAt" },
            },
            count: { $sum: 1 },
          },
        },
        {
          $sort: { "_id.year": 1, "_id.month": 1 },
        },
      ])
      .toArray();

    res.json({
      totalServices,
      activeServices,
      featuredServices,
      recentServices,
      totalRevenue,
      serviceGrowth,
    });
  } catch (error) {
    console.error("Error fetching service statistics:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// POST create new service - Admin only
app.post("/services", verifyAdmin, async (req, res) => {
  const servicesCollection = client
    .db("SubidhaHomeService")
    .collection("services");
  const categoriesCollection = client
    .db("SubidhaHomeService")
    .collection("categories");
  try {
    const {
      serviceName,
      description,
      price,
      duration,
      category,
      icon,
      status = "active",
      isFeatured = false,
    } = req.body;

    // Validate required fields
    if (!serviceName || !description || !category) {
      return res.status(400).json({
        error: "Service name, description, and category are required",
      });
    }

    const newService = {
      serviceName,
      description,
      price: price ? parseFloat(price) : 0,
      duration: duration ? parseInt(duration) : null,
      category,
      icon: icon || null,
      status,
      isFeatured: Boolean(isFeatured),
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };

    const result = await servicesCollection.insertOne(newService);

    if (result.insertedId) {
      // Update category service count
      await categoriesCollection.updateOne(
        { _id: new ObjectId(category) },
        { $inc: { totalService: 1 } }
      );

      res.status(201).json({
        _id: result.insertedId,
        ...newService,
      });
    } else {
      res.status(500).json({ error: "Failed to create service" });
    }
  } catch (error) {
    console.error("Error creating service:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// PUT update service - Admin only
app.put("/services/:id", verifyAdmin, async (req, res) => {
  const servicesCollection = client
    .db("SubidhaHomeService")
    .collection("services");
  try {
    const serviceId = req.params.id;
    const updateData = req.body;

    console.log("PUT request received for service ID:", serviceId);
    console.log("Update data:", updateData);

    // Remove _id from update data if it exists
    if (updateData._id) {
      delete updateData._id;
    }

    // Add updatedAt timestamp
    updateData.updatedAt = new Date().toISOString();

    const result = await servicesCollection.updateOne(
      { _id: new ObjectId(serviceId) },
      { $set: updateData }
    );

    console.log("Update result:", result);

    if (result.matchedCount === 0) {
      return res.status(404).json({ error: "Service not found" });
    }

    if (result.modifiedCount > 0) {
      res.json({ message: "Service updated successfully" });
    } else {
      res.json({ message: "No changes made to service" });
    }
  } catch (error) {
    console.error("Error updating service:", error);
    res
      .status(500)
      .json({ error: "Internal Server Error", details: error.message });
  }
});

// DELETE service
app.delete("/delete-service/:id", verifyAdmin, async (req, res) => {
  const servicesCollection = client
    .db("SubidhaHomeService")
    .collection("services");
  const categoriesCollection = client
    .db("SubidhaHomeService")
    .collection("categories");
  try {
    const serviceId = req.params.id;

    // Get service details before deletion
    const service = await servicesCollection.findOne({
      _id: new ObjectId(serviceId),
    });

    if (!service) {
      return res.status(404).json({ error: "Service not found" });
    }

    const result = await servicesCollection.deleteOne({
      _id: new ObjectId(serviceId),
    });

    if (result.deletedCount > 0) {
      // Update category service count
      if (service.category) {
        await categoriesCollection.updateOne(
          { _id: new ObjectId(service.category) },
          { $inc: { totalService: -1 } }
        );
      }

      res.json({ message: "Service deleted successfully" });
    } else {
      res.status(500).json({ error: "Failed to delete service" });
    }
  } catch (error) {
    console.error("Error deleting service:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// GET single service by ID
app.get("/services/:id", async (req, res) => {
  const servicesCollection = client
    .db("SubidhaHomeService")
    .collection("services");
  try {
    const serviceId = req.params.id;

    const service = await servicesCollection.findOne({
      _id: new ObjectId(serviceId),
    });

    if (!service) {
      return res.status(404).json({ error: "Service not found" });
    }

    res.json(service);
  } catch (error) {
    console.error("Error fetching service:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// DELETE service - Admin only
app.delete("/services/:id", verifyAdmin, async (req, res) => {
  const servicesCollection = client
    .db("SubidhaHomeService")
    .collection("services");
  const categoriesCollection = client
    .db("SubidhaHomeService")
    .collection("categories");
  try {
    const serviceId = req.params.id;

    // Check if service exists
    const service = await servicesCollection.findOne({
      _id: new ObjectId(serviceId),
    });

    if (!service) {
      return res.status(404).json({ error: "Service not found" });
    }

    // Delete the service
    const result = await servicesCollection.deleteOne({
      _id: new ObjectId(serviceId),
    });

    if (result.deletedCount > 0) {
      // Update category service count
      await categoriesCollection.updateOne(
        { _id: new ObjectId(service.category) },
        { $inc: { totalService: -1 } }
      );

      res.json({ message: "Service deleted successfully" });
    } else {
      res.status(500).json({ error: "Failed to delete service" });
    }
  } catch (error) {
    console.error("Error deleting service:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// ==================== PROVIDER REGISTRATION ENDPOINT ====================

// Service Provider Registration Endpoint
app.post(
  "/providers/register",
  upload.fields([
    { name: "profilePhoto", maxCount: 1 },
    { name: "nidFront", maxCount: 1 },
    { name: "nidBack", maxCount: 1 },
    { name: "businessLicense", maxCount: 1 },
    { name: "portfolioImages", maxCount: 10 },
  ]),
  async (req, res) => {
    try {
      // Extract form data from request body
      const {
        // Personal Information
        fullName,
        email,
        phone,
        dateOfBirth,
        gender,
        nidNumber,

        // Business Information
        businessName,
        businessType,
        yearsOfExperience,
        serviceCategories,
        serviceAreas,

        // Location Information
        division,
        district,
        upazila,
        address,
        postalCode,

        // Bank Information
        bankName,
        accountNumber,
        accountHolderName,
        routingNumber,

        // Terms and Conditions
        agreeToTerms,
        agreeToDataProcessing,
        agreeToMarketing,
      } = req.body;

      // Handle uploaded files and upload to ImageBB
      const files = req.files;
      const documents = {
        profilePhoto: null,
        nidFront: null,
        nidBack: null,
        businessLicense: null,
        portfolioImages: [],
      };

      console.log("Uploaded files:", files);
      console.log("ImageBB enabled:", isImageBBEnabled);
      console.log("ImageBB API Key:", IMAGEBB_API_KEY ? "Present" : "Missing");

      // Check if ImageBB is properly configured
      if (!isImageBBEnabled || !IMAGEBB_API_KEY) {
        return res.status(500).json({
          error: "ImageBB service not configured",
          message:
            "File upload service is not available. Please contact support.",
        });
      }

      // Upload all files to ImageBB and save only URLs in database
      console.log("Uploading all documents to ImageBB...");

      // Upload profile photo
      if (files.profilePhoto) {
        const profilePhotoResult = await uploadToImageBB(
          files.profilePhoto[0].buffer,
          files.profilePhoto[0].originalname
        );
        if (profilePhotoResult.success) {
          documents.profilePhoto = profilePhotoResult.url;
          console.log(
            "✅ Profile photo uploaded to ImageBB:",
            profilePhotoResult.url
          );
        } else {
          console.error(
            "❌ Failed to upload profile photo to ImageBB:",
            profilePhotoResult.error
          );
          return res.status(500).json({
            error: "Failed to upload profile photo",
            message: "Please try again later",
          });
        }
      }

      // Upload NID front
      if (files.nidFront) {
        const nidFrontResult = await uploadToImageBB(
          files.nidFront[0].buffer,
          files.nidFront[0].originalname
        );
        if (nidFrontResult.success) {
          documents.nidFront = nidFrontResult.url;
          console.log("✅ NID front uploaded to ImageBB:", nidFrontResult.url);
        } else {
          console.error(
            "❌ Failed to upload NID front to ImageBB:",
            nidFrontResult.error
          );
          return res.status(500).json({
            error: "Failed to upload NID front",
            message: "Please try again later",
          });
        }
      }

      // Upload NID back
      if (files.nidBack) {
        const nidBackResult = await uploadToImageBB(
          files.nidBack[0].buffer,
          files.nidBack[0].originalname
        );
        if (nidBackResult.success) {
          documents.nidBack = nidBackResult.url;
          console.log("✅ NID back uploaded to ImageBB:", nidBackResult.url);
        } else {
          console.error(
            "❌ Failed to upload NID back to ImageBB:",
            nidBackResult.error
          );
          return res.status(500).json({
            error: "Failed to upload NID back",
            message: "Please try again later",
          });
        }
      }

      // Upload business license (optional)
      if (files.businessLicense) {
        const businessLicenseResult = await uploadToImageBB(
          files.businessLicense[0].buffer,
          files.businessLicense[0].originalname
        );
        if (businessLicenseResult.success) {
          documents.businessLicense = businessLicenseResult.url;
          console.log(
            "✅ Business license uploaded to ImageBB:",
            businessLicenseResult.url
          );
        } else {
          console.error(
            "❌ Failed to upload business license to ImageBB:",
            businessLicenseResult.error
          );
          return res.status(500).json({
            error: "Failed to upload business license",
            message: "Please try again later",
          });
        }
      }

      // Upload portfolio images
      if (files.portfolioImages && files.portfolioImages.length > 0) {
        console.log(
          `Uploading ${files.portfolioImages.length} portfolio images to ImageBB...`
        );
        for (let i = 0; i < files.portfolioImages.length; i++) {
          const file = files.portfolioImages[i];
          const portfolioResult = await uploadToImageBB(
            file.buffer,
            file.originalname
          );
          if (portfolioResult.success) {
            documents.portfolioImages.push(portfolioResult.url);
            console.log(
              `✅ Portfolio image ${i + 1} uploaded to ImageBB:`,
              portfolioResult.url
            );
          } else {
            console.error(
              `❌ Failed to upload portfolio image ${i + 1} to ImageBB:`,
              portfolioResult.error
            );
            return res.status(500).json({
              error: `Failed to upload portfolio image ${i + 1}`,
              message: "Please try again later",
            });
          }
        }
      }

      console.log("Processed documents with ImageBB URLs:", documents);

      // Validate required fields
      if (
        !fullName ||
        !email ||
        !phone ||
        !businessName ||
        !serviceCategories ||
        serviceCategories.length === 0
      ) {
        return res.status(400).json({
          error: "Missing required fields",
          required: [
            "fullName",
            "email",
            "phone",
            "businessName",
            "serviceCategories",
          ],
        });
      }

      // Check if provider already exists
      const providersCollection = client
        .db("SubidhaHomeService")
        .collection("providers");

      const existingProvider = await providersCollection.findOne({
        $or: [{ email: email }, { phone: phone }, { nidNumber: nidNumber }],
      });

      if (existingProvider) {
        return res.status(409).json({
          error: "Provider already exists",
          message:
            "A provider with this email, phone, or NID number is already registered",
        });
      }

      // Create provider document
      const providerData = {
        // Firebase UID for authentication
        uid: uid,

        // Personal Information
        fullName,
        email,
        phone,
        dateOfBirth,
        gender,
        nidNumber,

        // Business Information
        businessName,
        businessType,
        yearsOfExperience,
        serviceCategories: Array.isArray(serviceCategories)
          ? serviceCategories
          : [serviceCategories],
        serviceAreas: serviceAreas || [],

        // Location Information
        division,
        district,
        upazila,
        address,
        postalCode,

        // Bank Information
        bankName,
        accountNumber,
        accountHolderName,
        routingNumber,

        // Terms and Conditions
        agreeToTerms: agreeToTerms === "true" || agreeToTerms === true,
        agreeToDataProcessing:
          agreeToDataProcessing === "true" || agreeToDataProcessing === true,
        agreeToMarketing:
          agreeToMarketing === "true" || agreeToMarketing === true,

        // Status and Metadata
        status: "pending", // pending, approved, rejected
        registrationDate: new Date(),
        lastUpdated: new Date(),

        // Documents (ImageBB URLs only - no local files stored)
        documents: documents,

        // Provider Stats
        stats: {
          totalJobs: 0,
          completedJobs: 0,
          rating: 0,
          reviews: 0,
          earnings: 0,
        },
      };

      // Insert provider into database
      const result = await providersCollection.insertOne(providerData);

      if (result.insertedId) {
        res.status(201).json({
          success: true,
          message: "Provider registration submitted successfully",
          providerId: result.insertedId,
          status: "pending",
          message:
            "Your application is under review. We will contact you within 24-48 hours.",
        });
      } else {
        res.status(500).json({
          error: "Failed to register provider",
          message: "Please try again later",
        });
      }
    } catch (error) {
      console.error("Error registering provider:", error);
      res.status(500).json({
        error: "Internal Server Error",
        message: "Please try again later",
      });
    }
  }
);

run();

// ==================== LEGACY PROVIDER ENDPOINTS (for backward compatibility) ====================

// Get all providers (legacy endpoint for admin panel)
app.get("/providers", async (req, res) => {
  const providersCollection = client
    .db("SubidhaHomeService")
    .collection("providers");

  try {
    const { page = 1, limit = 10, status, category, search } = req.query;
    const skip = (parseInt(page) - 1) * parseInt(limit);

    // Build filter object
    let filter = {};
    if (status) {
      filter.status = status;
    }
    if (category) {
      filter.serviceCategories = { $in: [category] };
    }
    if (search) {
      filter.$or = [
        { fullName: { $regex: search, $options: "i" } },
        { email: { $regex: search, $options: "i" } },
        { phone: { $regex: search, $options: "i" } },
        { businessName: { $regex: search, $options: "i" } },
      ];
    }

    const providers = await providersCollection
      .find(filter)
      .skip(skip)
      .limit(parseInt(limit))
      .sort({ registrationDate: -1 })
      .toArray();

    const total = await providersCollection.countDocuments(filter);

    res.json({
      providers: providers,
      pagination: {
        currentPage: parseInt(page),
        totalPages: Math.ceil(total / parseInt(limit)),
        totalItems: total,
        itemsPerPage: parseInt(limit),
      },
    });
  } catch (error) {
    console.error("Error fetching providers:", error);
    res.status(500).json({
      error: "Internal Server Error",
      message: "Failed to fetch providers",
    });
  }
});

// Get single provider by ID (legacy endpoint)
app.get("/providers/:id", async (req, res) => {
  const providersCollection = client
    .db("SubidhaHomeService")
    .collection("providers");

  try {
    const { id } = req.params;

    if (!ObjectId.isValid(id)) {
      return res.status(400).json({
        error: "Invalid ID format",
      });
    }

    const provider = await providersCollection.findOne({
      _id: new ObjectId(id),
    });

    if (!provider) {
      return res.status(404).json({
        error: "Provider not found",
      });
    }

    res.json(provider);
  } catch (error) {
    console.error("Error fetching provider:", error);
    res.status(500).json({
      error: "Internal Server Error",
      message: "Failed to fetch provider",
    });
  }
});

// Update provider (legacy endpoint)
app.put("/providers/:id", async (req, res) => {
  const providersCollection = client
    .db("SubidhaHomeService")
    .collection("providers");

  try {
    const { id } = req.params;
    const updateData = req.body;

    if (!ObjectId.isValid(id)) {
      return res.status(400).json({
        error: "Invalid ID format",
      });
    }

    const result = await providersCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: { ...updateData, lastUpdated: new Date() } }
    );

    if (result.matchedCount === 0) {
      return res.status(404).json({
        error: "Provider not found",
      });
    }

    const updatedProvider = await providersCollection.findOne({
      _id: new ObjectId(id),
    });

    res.json(updatedProvider);
  } catch (error) {
    console.error("Error updating provider:", error);
    res.status(500).json({
      error: "Internal Server Error",
      message: "Failed to update provider",
    });
  }
});

// Delete provider (legacy endpoint)
app.delete("/providers/:id", async (req, res) => {
  const providersCollection = client
    .db("SubidhaHomeService")
    .collection("providers");

  try {
    const { id } = req.params;

    if (!ObjectId.isValid(id)) {
      return res.status(400).json({
        error: "Invalid ID format",
      });
    }

    const result = await providersCollection.deleteOne({
      _id: new ObjectId(id),
    });

    if (result.deletedCount === 0) {
      return res.status(404).json({
        error: "Provider not found",
      });
    }

    res.json({
      message: "Provider deleted successfully",
    });
  } catch (error) {
    console.error("Error deleting provider:", error);
    res.status(500).json({
      error: "Internal Server Error",
      message: "Failed to delete provider",
    });
  }
});

// ==================== USER ROLE CHECK ENDPOINTS ====================

// Check if user is a provider
app.get("/api/check-provider/:uid", async (req, res) => {
  const providersCollection = client
    .db("SubidhaHomeService")
    .collection("providers");

  try {
    const { uid } = req.params;

    if (!uid) {
      return res.status(400).json({
        success: false,
        message: "User ID is required",
      });
    }

    // Check if user exists in providers collection
    // Since database doesn't have uid field, prioritize email search
    let provider = null;

    // If the identifier looks like an email, search by email first
    if (uid.includes("@")) {
      provider = await providersCollection.findOne({ email: uid });
      console.log("Search by email (primary) result:", provider);
    }

    // If not found by email, try by uid (in case some records have uid field)
    if (!provider) {
      provider = await providersCollection.findOne({ uid: uid });
      console.log("Search by UID result:", provider);
    }

    // If still not found, try by _id (ObjectId)
    if (!provider) {
      try {
        provider = await providersCollection.findOne({
          _id: new ObjectId(uid),
        });
        console.log("Search by ObjectId result:", provider);
      } catch (error) {
        console.log("ObjectId search failed:", error.message);
        // uid is not a valid ObjectId, continue
      }
    }

    console.log("Provider search result:", provider);

    if (provider) {
      return res.status(200).json({
        success: true,
        isProvider: true,
        providerData: {
          _id: provider._id,
          fullName: provider.fullName || provider.displayName || provider.name,
          email: provider.email,
          phone: provider.phone,
          businessName: provider.businessName || provider.companyName,
          status: provider.status || "approved",
          serviceCategories: provider.serviceCategories || [],
          address: provider.address || {},
        },
      });
    } else {
      return res.status(200).json({
        success: true,
        isProvider: false,
        message: "User is not a registered provider",
      });
    }
  } catch (error) {
    console.error("Error checking provider status:", error);
    return res.status(500).json({
      success: false,
      message: "Internal server error",
      error: error.message,
    });
  }
});

// Check if user is an admin
app.get("/api/check-admin/:uid", async (req, res) => {
  const usersCollection = client.db("SubidhaHomeService").collection("users");

  try {
    const { uid } = req.params;

    if (!uid) {
      return res.status(400).json({
        success: false,
        message: "User ID is required",
      });
    }

    // Check if user exists and has admin role
    // Support both UID and email search
    let user = null;

    // If the identifier looks like an email, search by email first
    if (uid.includes("@")) {
      user = await usersCollection.findOne({ email: uid });
      console.log("Admin search by email result:", user);
    }

    // If not found by email, try by uid
    if (!user) {
      user = await usersCollection.findOne({ uid: uid });
      console.log("Admin search by UID result:", user);
    }

    if (user && user.role === "admin") {
      return res.status(200).json({
        success: true,
        isAdmin: true,
        userData: {
          uid: user.uid,
          displayName: user.displayName,
          email: user.email,
          role: user.role,
        },
      });
    } else {
      return res.status(200).json({
        success: true,
        isAdmin: false,
        message: "User is not an admin",
      });
    }
  } catch (error) {
    console.error("Error checking admin status:", error);
    return res.status(500).json({
      success: false,
      message: "Internal server error",
      error: error.message,
    });
  }
});

// ==================== SERVICE PROVIDER MANAGEMENT ENDPOINTS ====================

// Get all service providers (Admin only)
app.get("/api/service-providers", async (req, res) => {
  const providersCollection = client
    .db("SubidhaHomeService")
    .collection("providers");

  try {
    const {
      page = 1,
      limit = 10,
      status,
      category,
      search,
      division,
      district,
      upazila,
      serviceCategory,
    } = req.query;
    const skip = (parseInt(page) - 1) * parseInt(limit);

    // Build filter object
    let filter = {};
    if (status) {
      filter.status = status;
    }
    if (category) {
      filter.serviceCategories = { $in: [category] };
    }
    if (serviceCategory) {
      filter.serviceCategories = { $in: [serviceCategory] };
    }
    if (search) {
      filter.$or = [
        { fullName: { $regex: search, $options: "i" } },
        { email: { $regex: search, $options: "i" } },
        { phone: { $regex: search, $options: "i" } },
        { businessName: { $regex: search, $options: "i" } },
      ];
    }

    // Location-based filtering
    if (division || district || upazila) {
      filter.$and = filter.$and || [];

      if (division) {
        filter.$and.push({
          $or: [
            { "address.division": { $regex: division, $options: "i" } },
            { division: { $regex: division, $options: "i" } },
          ],
        });
      }

      if (district) {
        filter.$and.push({
          $or: [
            { "address.district": { $regex: district, $options: "i" } },
            { district: { $regex: district, $options: "i" } },
          ],
        });
      }

      if (upazila) {
        filter.$and.push({
          $or: [
            { "address.upazila": { $regex: upazila, $options: "i" } },
            { upazila: { $regex: upazila, $options: "i" } },
          ],
        });
      }
    }

    const providers = await providersCollection
      .find(filter)
      .skip(skip)
      .limit(parseInt(limit))
      .sort({ registrationDate: -1 })
      .toArray();

    const total = await providersCollection.countDocuments(filter);

    res.json({
      success: true,
      data: providers,
      pagination: {
        currentPage: parseInt(page),
        totalPages: Math.ceil(total / parseInt(limit)),
        totalItems: total,
        itemsPerPage: parseInt(limit),
      },
    });
  } catch (error) {
    console.error("Error fetching service providers:", error);
    res.status(500).json({
      success: false,
      error: "Internal Server Error",
      message: "Failed to fetch service providers",
    });
  }
});

// Get service provider by ID
app.get("/api/service-providers/:id", async (req, res) => {
  const providersCollection = client
    .db("SubidhaHomeService")
    .collection("providers");

  try {
    const { id } = req.params;

    if (!ObjectId.isValid(id)) {
      return res.status(400).json({
        success: false,
        error: "Invalid ID format",
      });
    }

    const provider = await providersCollection.findOne({
      _id: new ObjectId(id),
    });

    if (!provider) {
      return res.status(404).json({
        success: false,
        error: "Service provider not found",
      });
    }

    res.json({
      success: true,
      data: provider,
    });
  } catch (error) {
    console.error("Error fetching service provider:", error);
    res.status(500).json({
      success: false,
      error: "Internal Server Error",
      message: "Failed to fetch service provider",
    });
  }
});

// Update service provider status (Admin only)
app.put("/api/service-providers/:id/status", async (req, res) => {
  const providersCollection = client
    .db("SubidhaHomeService")
    .collection("providers");

  try {
    const { id } = req.params;
    const { status, reason } = req.body;

    if (!ObjectId.isValid(id)) {
      return res.status(400).json({
        success: false,
        error: "Invalid ID format",
      });
    }

    const validStatuses = ["pending", "approved", "rejected", "suspended"];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({
        success: false,
        error: "Invalid status",
        message:
          "Status must be one of: pending, approved, rejected, suspended",
      });
    }

    const updateData = {
      status: status,
      lastUpdated: new Date(),
    };

    if (reason) {
      updateData.statusReason = reason;
    }

    if (status === "approved") {
      updateData.approvalDate = new Date();
    }

    const result = await providersCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: updateData }
    );

    if (result.matchedCount === 0) {
      return res.status(404).json({
        success: false,
        error: "Service provider not found",
      });
    }

    if (result.modifiedCount === 0) {
      return res.status(400).json({
        success: false,
        error: "No changes made",
        message:
          "Service provider status is already set to the requested status",
      });
    }

    // Get updated provider data
    const updatedProvider = await providersCollection.findOne({
      _id: new ObjectId(id),
    });

    res.json({
      success: true,
      message: `Service provider status updated to ${status}`,
      data: updatedProvider,
    });
  } catch (error) {
    console.error("Error updating service provider status:", error);
    res.status(500).json({
      success: false,
      error: "Internal Server Error",
      message: "Failed to update service provider status",
    });
  }
});

// Delete service provider (Admin only)
app.delete("/api/service-providers/:id", async (req, res) => {
  const providersCollection = client
    .db("SubidhaHomeService")
    .collection("providers");

  try {
    const { id } = req.params;

    if (!ObjectId.isValid(id)) {
      return res.status(400).json({
        success: false,
        error: "Invalid ID format",
      });
    }

    const result = await providersCollection.deleteOne({
      _id: new ObjectId(id),
    });

    if (result.deletedCount === 0) {
      return res.status(404).json({
        success: false,
        error: "Service provider not found",
      });
    }

    res.json({
      success: true,
      message: "Service provider deleted successfully",
    });
  } catch (error) {
    console.error("Error deleting service provider:", error);
    res.status(500).json({
      success: false,
      error: "Internal Server Error",
      message: "Failed to delete service provider",
    });
  }
});

// ==================== ADMIN USER MANAGEMENT ENDPOINTS ====================

// Get user statistics for admin dashboard
app.get("/admin/users/stats", verifyAdmin, async (req, res) => {
  try {
    const totalUsers = await usersCollection.estimatedDocumentCount();
    const activeUsers = await usersCollection.countDocuments({
      status: "active",
    });
    const inactiveUsers = await usersCollection.countDocuments({
      status: "inactive",
    });
    const suspendedUsers = await usersCollection.countDocuments({
      status: "suspended",
    });

    // Get recent registrations (last 30 days)
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
    const recentRegistrations = await usersCollection.countDocuments({
      createdAt: { $gte: thirtyDaysAgo },
    });

    // Get users by role
    const customers = await usersCollection.countDocuments({
      role: "customer",
    });
    const providers = await usersCollection.countDocuments({
      role: "provider",
    });
    const admins = await usersCollection.countDocuments({ role: "admin" });

    res.json({
      totalUsers,
      activeUsers,
      inactiveUsers,
      suspendedUsers,
      recentRegistrations,
      usersByRole: {
        customers,
        providers,
        admins,
      },
    });
  } catch (error) {
    console.error("Error fetching user stats:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Bulk update user status
app.put("/admin/users/bulk-status", verifyAdmin, async (req, res) => {
  try {
    const { userIds, status } = req.body;

    if (!userIds || !Array.isArray(userIds) || !status) {
      return res.status(400).json({ error: "Invalid request data" });
    }

    const result = await usersCollection.updateMany(
      { _id: { $in: userIds.map((id) => new ObjectId(id)) } },
      { $set: { status, updatedAt: new Date() } }
    );

    res.json({
      success: true,
      modifiedCount: result.modifiedCount,
      message: `Updated ${result.modifiedCount} users to ${status} status`,
    });
  } catch (error) {
    console.error("Error bulk updating user status:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Bulk delete users
app.delete("/admin/users/bulk-delete", verifyAdmin, async (req, res) => {
  try {
    const { userIds } = req.body;

    if (!userIds || !Array.isArray(userIds)) {
      return res.status(400).json({ error: "Invalid request data" });
    }

    // Find users to get their UIDs for Firebase deletion
    const users = await usersCollection
      .find({
        _id: { $in: userIds.map((id) => new ObjectId(id)) },
      })
      .toArray();

    let firebaseDeletedCount = 0;
    const firebaseErrors = [];

    // Delete from Firebase
    for (const user of users) {
      if (user.uid && admin.apps.length > 0) {
        try {
          await admin.auth().deleteUser(user.uid);
          firebaseDeletedCount++;
        } catch (firebaseErr) {
          firebaseErrors.push({ userId: user._id, error: firebaseErr.message });
        }
      }
    }

    // Delete from database
    const result = await usersCollection.deleteMany({
      _id: { $in: userIds.map((id) => new ObjectId(id)) },
    });

    res.json({
      success: true,
      deletedCount: result.deletedCount,
      firebaseDeletedCount,
      firebaseErrors,
      message: `Deleted ${result.deletedCount} users from database`,
    });
  } catch (error) {
    console.error("Error bulk deleting users:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Get user details with extended information
app.get("/admin/users/:id/details", verifyAdmin, async (req, res) => {
  try {
    const userId = req.params.id;

    if (!ObjectId.isValid(userId)) {
      return res.status(400).json({ error: "Invalid user ID format" });
    }

    const user = await usersCollection.findOne({ _id: new ObjectId(userId) });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Get user's booking history
    const bookings = await bookingCollection
      .find({
        customerId: user.uid,
      })
      .toArray();

    // Get user's reviews
    const reviews = await reviewCollection
      .find({
        userId: user.uid,
      })
      .toArray();

    // Get user's payments
    const payments = await paymentCollection
      .find({
        userId: user.uid,
      })
      .toArray();

    res.json({
      user,
      statistics: {
        totalBookings: bookings.length,
        completedBookings: bookings.filter((b) => b.status === "completed")
          .length,
        totalReviews: reviews.length,
        totalSpent: payments.reduce(
          (sum, payment) => sum + (payment.amount || 0),
          0
        ),
        averageRating:
          reviews.length > 0
            ? (
                reviews.reduce((sum, review) => sum + (review.rating || 0), 0) /
                reviews.length
              ).toFixed(1)
            : 0,
      },
      recentActivity: {
        bookings: bookings.slice(-5),
        reviews: reviews.slice(-5),
        payments: payments.slice(-5),
      },
    });
  } catch (error) {
    console.error("Error fetching user details:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Update user role (admin only)
app.put("/admin/users/:id/role", verifyAdmin, async (req, res) => {
  try {
    const userId = req.params.id;
    const { role } = req.body;

    if (!ObjectId.isValid(userId)) {
      return res.status(400).json({ error: "Invalid user ID format" });
    }

    if (!["customer", "provider", "admin"].includes(role)) {
      return res.status(400).json({ error: "Invalid role" });
    }

    const result = await usersCollection.updateOne(
      { _id: new ObjectId(userId) },
      { $set: { role, updatedAt: new Date() } }
    );

    if (result.modifiedCount === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json({
      success: true,
      message: `User role updated to ${role}`,
    });
  } catch (error) {
    console.error("Error updating user role:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Send notification to user
app.post("/admin/users/:id/notify", verifyAdmin, async (req, res) => {
  try {
    const userId = req.params.id;
    const { subject, message, type = "info" } = req.body;

    if (!ObjectId.isValid(userId)) {
      return res.status(400).json({ error: "Invalid user ID format" });
    }

    const user = await usersCollection.findOne({ _id: new ObjectId(userId) });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Create notification record
    const notification = {
      userId: user.uid,
      type,
      subject,
      message,
      createdAt: new Date(),
      read: false,
      sentBy: req.adminUser.uid,
    };

    // Store notification in database
    await notificationCollection.insertOne(notification);

    // Send email notification if user has email
    if (user.email) {
      try {
        const mailOptions = {
          from: process.env.EMAIL_USER,
          to: user.email,
          subject: `Subidha: ${subject}`,
          html: `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
              <h2 style="color: #3b82f6;">Subidha Home Services</h2>
              <div style="background: #f8fafc; padding: 20px; border-radius: 8px; margin: 20px 0;">
                <h3 style="color: #1f2937; margin-top: 0;">${subject}</h3>
                <p style="color: #4b5563; line-height: 1.6;">${message}</p>
              </div>
              <p style="color: #6b7280; font-size: 14px;">
                This is an automated message from Subidha Home Services.
              </p>
            </div>
          `,
        };

        await transporter.sendMail(mailOptions);
      } catch (emailError) {
        console.error("Error sending email notification:", emailError);
      }
    }

    res.json({
      success: true,
      message: "Notification sent successfully",
    });
  } catch (error) {
    console.error("Error sending notification:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Get user analytics
app.get("/admin/users/analytics", verifyAdmin, async (req, res) => {
  try {
    const { range = "30d" } = req.query;

    // Calculate date range
    const now = new Date();
    let startDate;

    switch (range) {
      case "7d":
        startDate = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
        break;
      case "30d":
        startDate = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
        break;
      case "90d":
        startDate = new Date(now.getTime() - 90 * 24 * 60 * 60 * 1000);
        break;
      case "1y":
        startDate = new Date(now.getTime() - 365 * 24 * 60 * 60 * 1000);
        break;
      default:
        startDate = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
    }

    // Get analytics data
    const newRegistrations = await usersCollection.countDocuments({
      createdAt: { $gte: startDate },
    });

    const activeUsers = await usersCollection.countDocuments({
      status: "active",
      lastActive: { $gte: startDate },
    });

    // Calculate engagement rate (users who made bookings in the period)
    const totalUsers = await usersCollection.estimatedDocumentCount();
    const engagedUsers = await usersCollection.countDocuments({
      _id: {
        $in: await bookingCollection.distinct("customerId", {
          createdAt: { $gte: startDate },
        }),
      },
    });

    const engagementRate =
      totalUsers > 0 ? Math.round((engagedUsers / totalUsers) * 100) : 0;

    // Calculate retention rate (users who were active in previous period and current period)
    const previousStartDate = new Date(
      startDate.getTime() - (now.getTime() - startDate.getTime())
    );
    const retainedUsers = await usersCollection.countDocuments({
      createdAt: { $lt: startDate },
      lastActive: { $gte: startDate },
    });

    const previousPeriodUsers = await usersCollection.countDocuments({
      createdAt: { $lt: startDate },
    });

    const retentionRate =
      previousPeriodUsers > 0
        ? Math.round((retainedUsers / previousPeriodUsers) * 100)
        : 0;

    // Get age demographics (mock data for now)
    const demographics = {
      ageGroups: {
        under25: 35,
        age25to40: 45,
        over40: 20,
      },
    };

    res.json({
      newRegistrations,
      activeUsers,
      engagementRate,
      retentionRate,
      demographics,
      period: range,
      startDate,
      endDate: now,
    });
  } catch (error) {
    console.error("Error fetching user analytics:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ==================== BOOKING SYSTEM ENDPOINTS ====================

// SSL Commerz configuration
const isProduction = process.env.NODE_ENV === "production";
const sslCommerzConfig = {
  store_id: process.env.SSL_STORE_ID || "subid6647a15c98bc9",
  store_passwd: process.env.SSL_STORE_PASSWORD || "subid6647a15c98bc9@ssl",
  is_live: isProduction, // Set to true for production

  // URLs based on environment
  success_url:
    process.env.SSL_SUCCESS_URL ||
    (isProduction
      ? "https://yourdomain.com/payment-success.html"
      : "http://localhost:5000/payment-success.html"),
  fail_url:
    process.env.SSL_FAIL_URL ||
    (isProduction
      ? "https://yourdomain.com/ssl-payment/failed"
      : "http://localhost:5173/ssl-payment/failed"),
  cancel_url:
    process.env.SSL_CANCEL_URL ||
    (isProduction
      ? "https://yourdomain.com/ssl-payment/cancelled"
      : "http://localhost:5173/ssl-payment/cancelled"),
  ipn_url:
    process.env.SSL_IPN_URL ||
    (isProduction
      ? "https://yourdomain.com/api/bookings/ssl-ipn"
      : "http://localhost:5000/api/bookings/ssl-ipn"),
};

// Create SSL Commerz instance
const sslcommerz = new SSLCommerzPayment(
  sslCommerzConfig.store_id,
  sslCommerzConfig.store_passwd,
  sslCommerzConfig.is_live
);

// Test SSL Commerz configuration
console.log("🔧 SSL Commerz Configuration:", {
  store_id: sslCommerzConfig.store_id,
  is_live: sslCommerzConfig.is_live,
  success_url: sslCommerzConfig.success_url,
  fail_url: sslCommerzConfig.fail_url,
  cancel_url: sslCommerzConfig.cancel_url,
  ipn_url: sslCommerzConfig.ipn_url,
});

// Generate unique booking ID
const generateBookingId = () => {
  const timestamp = Date.now().toString(36);
  const random = Math.random().toString(36).substr(2, 5);
  return `BK-${timestamp}-${random}`.toUpperCase();
};

// Create new booking endpoint
app.post("/api/bookings", async (req, res) => {
  try {
    console.log("📝 Booking request received:", req.body);

    const {
      customerId,
      providerId,
      serviceId,
      serviceName,
      servicePrice,
      bookingDate,
      bookingTime,
      address,
      serviceArea,
      notes,
      customerInfo,
      paymentMethod = "online",
    } = req.body;

    // Validate required fields
    if (
      !customerId ||
      !providerId ||
      !serviceId ||
      !bookingDate ||
      !bookingTime ||
      !address
    ) {
      console.log("❌ Missing required fields:", {
        customerId: !!customerId,
        providerId: !!providerId,
        serviceId: !!serviceId,
        bookingDate: !!bookingDate,
        bookingTime: !!bookingTime,
        address: !!address,
      });
      return res.status(400).json({
        error: "Missing required fields",
        message: "Please provide all required booking information",
      });
    }

    // Fetch service details to get the service photo
    const service = await servicesCollection.findOne(
      { _id: new ObjectId(serviceId) },
      { projection: { name: 1, image: 1, photoURL: 1 } }
    );

    // Generate booking ID
    const bookingId = generateBookingId();

    // Create booking object
    const booking = {
      bookingId,
      customerId,
      providerId,
      serviceId,
      serviceName,
      servicePrice: parseFloat(servicePrice),
      bookingDate: new Date(bookingDate),
      bookingTime,
      address,
      serviceArea: serviceArea || {},
      notes: notes || "",
      customerInfo,
      status: "broadcast_pending", // Start with broadcast pending status
      paymentStatus: "pending",
      paymentMethod,
      broadcastStatus: "active", // Mark as active for broadcasting
      broadcastExpiry: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours expiry
      createdAt: new Date(),
      updatedAt: new Date(),
      // SSL Commerz specific fields
      sslTransactionId: null,
      sslSessionKey: null,
      sslValId: null,
    };

    // Insert booking into database
    console.log("💾 Inserting booking into database:", booking);
    const result = await bookingCollection.insertOne(booking);
    console.log("✅ Booking inserted successfully:", result.insertedId);

    // Booking created successfully - no broadcasting needed
    console.log("✅ Booking created successfully");

    // Handle payment based on method
    if (paymentMethod === "online") {
      console.log("💳 Processing online payment...");

      // Prepare SSL Commerz payment data
      const paymentData = {
        total_amount: booking.servicePrice,
        currency: "BDT",
        tran_id: bookingId,
        success_url: sslCommerzConfig.success_url,
        fail_url: sslCommerzConfig.fail_url,
        cancel_url: sslCommerzConfig.cancel_url,
        ipn_url: sslCommerzConfig.ipn_url,
        cus_name: customerInfo?.name || "Customer",
        cus_email: customerInfo?.email || "customer@example.com",
        cus_add1: address,
        cus_city: "Dhaka",
        cus_country: "Bangladesh",
        cus_phone: customerInfo?.phone || "01234567890",
        ship_name: customerInfo?.name || "Customer",
        ship_add1: address,
        ship_city: "Dhaka",
        ship_country: "Bangladesh",
        value_a: bookingId, // Booking ID
        value_b: providerId, // Provider ID
        value_c: customerId, // Customer ID
        value_d: serviceId, // Service ID
      };

      console.log("🔧 SSL Commerz payment data:", paymentData);

      try {
        // For development, use test payment page directly
        if (!isProduction) {
          const testPaymentUrl = `http://localhost:5173/booking/success?tran_id=${bookingId}&total_amount=${paymentData.total_amount}&currency=${paymentData.currency}&cus_name=${paymentData.cus_name}&cus_email=${paymentData.cus_email}`;

          // Update booking with test payment info
          await bookingCollection.updateOne(
            { _id: result.insertedId },
            {
              $set: {
                sslSessionKey: bookingId,
                paymentStatus: "pending",
                updatedAt: new Date(),
              },
            }
          );

          return res.json({
            success: true,
            message: "Booking created successfully. Please complete payment.",
            bookingId,
            paymentUrl: testPaymentUrl,
            sessionKey: bookingId,
          });
        }

        // Initialize SSL Commerz payment for production
        console.log("🚀 Initializing SSL Commerz payment...");
        console.log("🔧 SSL Commerz instance:", sslcommerz);
        console.log("🔧 SSL Commerz config:", sslCommerzConfig);
        console.log("🔧 Payment data:", paymentData);

        const sslResponse = await sslcommerz.init(paymentData);
        console.log("📡 SSL Commerz response:", sslResponse);

        if (sslResponse && sslResponse.status === "SUCCESS") {
          // Update booking with SSL session key
          await bookingCollection.updateOne(
            { _id: result.insertedId },
            {
              $set: {
                sslSessionKey: sslResponse.sessionkey,
                updatedAt: new Date(),
              },
            }
          );

          return res.json({
            success: true,
            message: "Booking created successfully. Please complete payment.",
            bookingId,
            paymentUrl: sslResponse.GatewayPageURL,
            sessionKey: sslResponse.sessionkey,
          });
        } else {
          console.log("❌ SSL Commerz payment failed:", sslResponse);

          // Return error for online payment if SSL Commerz fails
          return res.status(400).json({
            success: false,
            message:
              "Payment gateway is temporarily unavailable. Please try again later or select cash payment.",
            error: "SSL_COMMERZ_FAILED",
            details: sslResponse.failedreason || "Unknown SSL Commerz error",
          });
        }
      } catch (sslError) {
        console.error("❌ SSL Commerz Error:", sslError);

        // For development, use test payment page as fallback
        if (!isProduction) {
          console.log(
            "🔄 Using test payment page as fallback for development..."
          );
          const testPaymentUrl = `http://localhost:5173/booking/success?tran_id=${bookingId}&total_amount=${paymentData.total_amount}&currency=${paymentData.currency}&cus_name=${paymentData.cus_name}&cus_email=${paymentData.cus_email}`;

          return res.json({
            success: true,
            message: "Booking created successfully. Please complete payment.",
            bookingId,
            paymentUrl: testPaymentUrl,
            sessionKey: bookingId,
          });
        }

        // For production, return error
        return res.status(400).json({
          success: false,
          message:
            "Payment gateway is temporarily unavailable. Please try again later or select cash payment.",
          error: "SSL_COMMERZ_ERROR",
          details: sslError.message || "SSL Commerz initialization failed",
        });
      }
    } else {
      // Cash on service payment
      return res.json({
        success: true,
        message:
          "Booking created successfully. Payment will be collected on service.",
        bookingId,
        booking: {
          ...booking,
          _id: result.insertedId,
        },
      });
    }
  } catch (error) {
    console.error("❌ Error creating booking:", error);
    console.error("❌ Error stack:", error.stack);
    res.status(500).json({
      error: "Internal server error",
      message: "Unable to create booking at this time",
      details: error.message,
    });
  }
});

// Generate and download receipt
app.get("/api/receipt/:bookingId", async (req, res) => {
  try {
    const { bookingId } = req.params;
    console.log("🧾 Generating receipt for booking:", bookingId);

    // Find the booking
    const booking = await bookingCollection.findOne({ bookingId });
    if (!booking) {
      return res.status(404).json({
        success: false,
        message: "Booking not found",
      });
    }

    // Check if payment is completed
    if (booking.paymentStatus !== "paid") {
      return res.status(400).json({
        success: false,
        message: "Receipt can only be generated for completed payments",
      });
    }

    // Generate receipt data
    const receiptData = {
      receiptNumber: `RCP-${bookingId.slice(-8).toUpperCase()}`,
      bookingId: booking.bookingId,
      serviceName: booking.serviceName,
      customerName: booking.customerName,
      customerEmail: booking.customerEmail,
      customerPhone: booking.customerPhone,
      providerName:
        booking.provider?.businessName ||
        booking.provider?.name ||
        "Service Provider",
      servicePrice: booking.servicePrice,
      paymentMethod: booking.paymentMethod || "Online Payment",
      paymentStatus: booking.paymentStatus,
      bookingDate: booking.bookingDate,
      bookingTime: booking.bookingTime,
      address: booking.address,
      createdAt: booking.createdAt,
      processedAt: booking.updatedAt || booking.createdAt,
      gateway: "SSL Commerz",
      companyName: "SUBIDHA Home Services",
      companyAddress: "Dhaka, Bangladesh",
      companyPhone: "+880 1234 567890",
      companyEmail: "info@subidha.com",
    };

    // Generate HTML receipt
    const htmlReceipt = generateReceiptHTML(receiptData);

    // Set headers for PDF download
    res.setHeader("Content-Type", "text/html");
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="receipt-${bookingId}.html"`
    );

    res.send(htmlReceipt);
  } catch (error) {
    console.error("❌ Error generating receipt:", error);
    res.status(500).json({
      success: false,
      message: "Failed to generate receipt",
      error: error.message,
    });
  }
});

// Helper function to generate receipt HTML
function generateReceiptHTML(data) {
  const formatDate = (date) => {
    return new Date(date).toLocaleDateString("en-US", {
      year: "numeric",
      month: "long",
      day: "numeric",
    });
  };

  const formatTime = (time) => {
    return new Date(time).toLocaleTimeString("en-US", {
      hour: "2-digit",
      minute: "2-digit",
      hour12: true,
    });
  };

  return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Receipt - ${data.receiptNumber}</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Arial', sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f8f9fa;
            padding: 20px;
        }
        
        .receipt-container {
            max-width: 800px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #0d9488, #14b8a6);
            color: white;
            padding: 30px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            font-weight: bold;
        }
        
        .header p {
            font-size: 1.1em;
            opacity: 0.9;
        }
        
        .receipt-number {
            background: #f1f5f9;
            padding: 15px;
            text-align: center;
            border-bottom: 2px solid #e2e8f0;
        }
        
        .receipt-number h2 {
            color: #0d9488;
            font-size: 1.5em;
            font-weight: bold;
        }
        
        .content {
            padding: 30px;
        }
        
        .section {
            margin-bottom: 30px;
        }
        
        .section h3 {
            color: #0d9488;
            font-size: 1.3em;
            margin-bottom: 15px;
            border-bottom: 2px solid #e2e8f0;
            padding-bottom: 5px;
        }
        
        .info-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
        }
        
        .info-item {
            margin-bottom: 15px;
        }
        
        .info-label {
            font-weight: bold;
            color: #64748b;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .info-value {
            font-size: 1.1em;
            color: #1e293b;
            margin-top: 5px;
        }
        
        .amount-section {
            background: #f8fafc;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #0d9488;
        }
        
        .amount-grid {
            display: grid;
            grid-template-columns: 1fr auto;
            gap: 15px;
            align-items: center;
        }
        
        .amount-label {
            font-size: 1.2em;
            font-weight: bold;
            color: #1e293b;
        }
        
        .amount-value {
            font-size: 2em;
            font-weight: bold;
            color: #0d9488;
        }
        
        .status-badge {
            display: inline-block;
            padding: 8px 16px;
            border-radius: 20px;
            font-size: 0.9em;
            font-weight: bold;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .status-paid {
            background: #dcfce7;
            color: #166534;
        }
        
        .footer {
            background: #f8fafc;
            padding: 20px;
            text-align: center;
            border-top: 1px solid #e2e8f0;
        }
        
        .footer p {
            color: #64748b;
            font-size: 0.9em;
        }
        
        .company-info {
            margin-top: 15px;
            padding-top: 15px;
            border-top: 1px solid #e2e8f0;
        }
        
        .company-info p {
            margin-bottom: 5px;
        }
        
        @media print {
            body {
                background: white;
                padding: 0;
            }
            
            .receipt-container {
                box-shadow: none;
                border-radius: 0;
            }
        }
        
        @media (max-width: 768px) {
            .info-grid {
                grid-template-columns: 1fr;
            }
            
            .amount-grid {
                grid-template-columns: 1fr;
                text-align: center;
            }
        }
    </style>
</head>
<body>
    <div class="receipt-container">
        <div class="header">
            <h1>${data.companyName}</h1>
            <p>Professional Home Services</p>
        </div>
        
        <div class="receipt-number">
            <h2>Receipt #${data.receiptNumber}</h2>
        </div>
        
        <div class="content">
            <div class="section">
                <h3>Service Details</h3>
                <div class="info-grid">
                    <div class="info-item">
                        <div class="info-label">Service Name</div>
                        <div class="info-value">${data.serviceName}</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Booking ID</div>
                        <div class="info-value">${data.bookingId}</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Service Provider</div>
                        <div class="info-value">${data.providerName}</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Service Date</div>
                        <div class="info-value">${formatDate(
                          data.bookingDate
                        )}</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Service Time</div>
                        <div class="info-value">${formatTime(
                          data.bookingTime
                        )}</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Service Location</div>
                        <div class="info-value">${data.address}</div>
                    </div>
                </div>
            </div>
            
            <div class="section">
                <h3>Customer Information</h3>
                <div class="info-grid">
                    <div class="info-item">
                        <div class="info-label">Customer Name</div>
                        <div class="info-value">${data.customerName}</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Email</div>
                        <div class="info-value">${data.customerEmail}</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Phone</div>
                        <div class="info-value">${data.customerPhone}</div>
                    </div>
                </div>
            </div>
            
            <div class="section">
                <h3>Payment Information</h3>
                <div class="amount-section">
                    <div class="amount-grid">
                        <div class="amount-label">Total Amount Paid</div>
                        <div class="amount-value">৳${data.servicePrice.toLocaleString()}</div>
                    </div>
                </div>
                <div class="info-grid" style="margin-top: 20px;">
                    <div class="info-item">
                        <div class="info-label">Payment Method</div>
                        <div class="info-value">${data.paymentMethod}</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Payment Status</div>
                        <div class="info-value">
                            <span class="status-badge status-paid">${data.paymentStatus.toUpperCase()}</span>
                        </div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Payment Gateway</div>
                        <div class="info-value">${data.gateway}</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Payment Date</div>
                        <div class="info-value">${formatDate(
                          data.processedAt
                        )}</div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="footer">
            <p>Thank you for choosing ${data.companyName}!</p>
            <p>This receipt serves as proof of payment for the service provided.</p>
            
            <div class="company-info">
                <p><strong>${data.companyName}</strong></p>
                <p>${data.companyAddress}</p>
                <p>Phone: ${data.companyPhone}</p>
                <p>Email: ${data.companyEmail}</p>
            </div>
        </div>
    </div>
</body>
</html>
  `;
}

// Get user payments
app.get("/api/user-payments/:userId", async (req, res) => {
  try {
    const { userId } = req.params;
    console.log("📊 Fetching payments for user:", userId);

    // Get user's bookings with payment information
    let bookings = await bookingCollection
      .find({ userId })
      .sort({ createdAt: -1 })
      .toArray();

    // If no bookings found with userId, try customerId
    if (bookings.length === 0) {
      bookings = await bookingCollection
        .find({ customerId: userId })
        .sort({ createdAt: -1 })
        .toArray();
    }

    // Transform bookings into payment records - only show actual payments
    console.log(`📊 Total bookings found: ${bookings.length}`);

    const payments = bookings
      .filter((booking) => {
        // Only show bookings that have actual payment information
        const hasPaymentStatus = booking.paymentStatus;
        const isPaidOrCompleted =
          booking.paymentStatus === "paid" ||
          booking.paymentStatus === "completed";
        const hasValidPrice = booking.servicePrice && booking.servicePrice > 0;

        console.log(`📊 Booking ${booking.bookingId}:`, {
          paymentStatus: booking.paymentStatus,
          servicePrice: booking.servicePrice,
          hasPaymentStatus,
          isPaidOrCompleted,
          hasValidPrice,
          willShow: hasPaymentStatus && isPaidOrCompleted && hasValidPrice,
        });

        return hasPaymentStatus && isPaidOrCompleted && hasValidPrice;
      })
      .map((booking) => ({
        _id: booking._id,
        transactionId: booking.bookingId,
        orderId: booking.bookingId,
        serviceName: booking.serviceName,
        amount: booking.servicePrice,
        paymentMethod: booking.paymentMethod || "online",
        status:
          booking.paymentStatus === "paid"
            ? "completed"
            : booking.paymentStatus || "pending",
        gateway: "SSL Commerz",
        description: `Payment for ${booking.serviceName}`,
        createdAt: booking.createdAt,
        processedAt:
          booking.paymentStatus === "paid" ? booking.updatedAt : null,
        fee: 0, // No processing fee for now
        providerName:
          booking.provider?.businessName ||
          booking.provider?.name ||
          "Service Provider",
      }));

    console.log(`📊 Final payments count: ${payments.length}`);
    res.json(payments);
  } catch (error) {
    console.error("❌ Error fetching user payments:", error);
    res.status(500).json({
      success: false,
      message: "Failed to fetch payment history",
      error: error.message,
    });
  }
});

// Payment Status Update Endpoints for Frontend Pages
app.post("/api/bookings/:bookingId/payment-success", async (req, res) => {
  try {
    const { bookingId } = req.params;
    const { val_id, amount, currency, payment_status } = req.body;

    console.log(`✅ Payment Success Update for booking: ${bookingId}`);

    const updateResult = await bookingCollection.updateOne(
      { bookingId: bookingId },
      {
        $set: {
          paymentStatus: "paid",
          sslValId: val_id,
          paymentAmount: amount,
          paymentCurrency: currency,
          paymentStatusUpdate: payment_status,
          updatedAt: new Date(),
        },
      }
    );

    if (updateResult.matchedCount > 0) {
      res.json({
        success: true,
        message: "Payment status updated successfully",
        bookingId,
      });
    } else {
      res.status(404).json({
        success: false,
        message: "Booking not found",
      });
    }
  } catch (error) {
    console.error("❌ Error updating payment success status:", error);
    res.status(500).json({
      success: false,
      message: "Failed to update payment status",
      error: error.message,
    });
  }
});

app.post("/api/bookings/:bookingId/payment-failed", async (req, res) => {
  try {
    const { bookingId } = req.params;
    const { error_reason, amount, currency, payment_status } = req.body;

    console.log(`❌ Payment Failed Update for booking: ${bookingId}`);

    const updateResult = await bookingCollection.updateOne(
      { bookingId: bookingId },
      {
        $set: {
          paymentStatus: "failed",
          paymentError: error_reason,
          paymentAmount: amount,
          paymentCurrency: currency,
          paymentStatusUpdate: payment_status,
          updatedAt: new Date(),
        },
      }
    );

    if (updateResult.matchedCount > 0) {
      res.json({
        success: true,
        message: "Payment failure status updated successfully",
        bookingId,
      });
    } else {
      res.status(404).json({
        success: false,
        message: "Booking not found",
      });
    }
  } catch (error) {
    console.error("❌ Error updating payment failed status:", error);
    res.status(500).json({
      success: false,
      message: "Failed to update payment status",
      error: error.message,
    });
  }
});

app.post("/api/bookings/:bookingId/payment-cancelled", async (req, res) => {
  try {
    const { bookingId } = req.params;
    const { amount, currency, payment_status } = req.body;

    console.log(`⚠️ Payment Cancelled Update for booking: ${bookingId}`);

    const updateResult = await bookingCollection.updateOne(
      { bookingId: bookingId },
      {
        $set: {
          paymentStatus: "cancelled",
          paymentAmount: amount,
          paymentCurrency: currency,
          paymentStatusUpdate: payment_status,
          updatedAt: new Date(),
        },
      }
    );

    if (updateResult.matchedCount > 0) {
      res.json({
        success: true,
        message: "Payment cancellation status updated successfully",
        bookingId,
      });
    } else {
      res.status(404).json({
        success: false,
        message: "Booking not found",
      });
    }
  } catch (error) {
    console.error("❌ Error updating payment cancelled status:", error);
    res.status(500).json({
      success: false,
      message: "Failed to update payment status",
      error: error.message,
    });
  }
});

// SSL Commerz IPN (Instant Payment Notification) handler
app.post("/api/bookings/ssl-ipn", async (req, res) => {
  try {
    const ipnData = req.body;
    console.log("SSL IPN Data:", ipnData);

    // Verify IPN data
    if (ipnData.status === "VALID" && ipnData.val_id) {
      const bookingId = ipnData.value_a; // Booking ID
      const providerId = ipnData.value_b;
      const customerId = ipnData.value_c;
      const serviceId = ipnData.value_d;

      // Update booking status - keep status as completed since service is already done
      const updateResult = await bookingCollection.updateOne(
        { bookingId: bookingId },
        {
          $set: {
            paymentStatus: "paid",
            sslTransactionId: ipnData.tran_id,
            sslValId: ipnData.val_id,
            // Keep status as completed since the service is already completed
            // Only update payment status to paid
            updatedAt: new Date(),
          },
        }
      );

      if (updateResult.modifiedCount > 0) {
        // Send notification to provider
        await notificationCollection.insertOne({
          userId: providerId,
          type: "booking_confirmed",
          title: "New Booking Confirmed",
          message: `You have a new booking (${bookingId}) from a customer.`,
          data: {
            bookingId,
            customerId,
            serviceId,
          },
          read: false,
          createdAt: new Date(),
        });

        // Send confirmation to customer
        await notificationCollection.insertOne({
          userId: customerId,
          type: "booking_confirmed",
          title: "Booking Confirmed",
          message: `Your booking (${bookingId}) has been confirmed and payment received.`,
          data: {
            bookingId,
            providerId,
            serviceId,
          },
          read: false,
          createdAt: new Date(),
        });

        console.log(`Booking ${bookingId} confirmed successfully`);
      }
    }

    // Always return success to SSL Commerz
    res.status(200).json({ status: "success" });
  } catch (error) {
    console.error("SSL IPN Error:", error);
    res.status(500).json({ status: "error" });
  }
});

// Get user's bookings
app.get("/api/bookings/user/:userId", async (req, res) => {
  try {
    const { userId } = req.params;
    const { status, page = 1, limit = 10 } = req.query;

    const query = { customerId: userId };
    if (status && status !== "all") {
      query.status = status;
    }

    const skip = (parseInt(page) - 1) * parseInt(limit);

    const bookings = await bookingCollection
      .find(query)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit))
      .toArray();

    // Get provider and service details for each booking
    const bookingsWithDetails = await Promise.all(
      bookings.map(async (booking) => {
        const provider = await usersCollection.findOne(
          { uid: booking.providerId },
          { projection: { name: 1, businessName: 1, photoURL: 1, phone: 1 } }
        );

        // Get service details
        const service = await servicesCollection.findOne(
          { _id: new ObjectId(booking.serviceId) },
          { projection: { name: 1, image: 1, photoURL: 1, description: 1 } }
        );

        return {
          ...booking,
          provider: provider || null,
          service: service || null,
        };
      })
    );

    const total = await bookingCollection.countDocuments(query);

    res.json({
      success: true,
      bookings: bookingsWithDetails,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / parseInt(limit)),
      },
    });
  } catch (error) {
    console.error("Error fetching user bookings:", error);
    res.status(500).json({
      error: "Internal server error",
      message: "Unable to fetch bookings",
    });
  }
});

// Get provider's bookings
app.get("/api/bookings/provider/:providerId", async (req, res) => {
  try {
    const { providerId } = req.params;
    const { status, page = 1, limit = 10 } = req.query;

    const query = { providerId };
    if (status && status !== "all") {
      query.status = status;
    }

    const skip = (parseInt(page) - 1) * parseInt(limit);

    const bookings = await bookingCollection
      .find(query)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit))
      .toArray();

    // Get customer details for each booking
    const bookingsWithCustomer = await Promise.all(
      bookings.map(async (booking) => {
        const customer = await usersCollection.findOne(
          { uid: booking.customerId },
          { projection: { name: 1, email: 1, phone: 1, photoURL: 1 } }
        );
        return {
          ...booking,
          customer: customer || null,
        };
      })
    );

    const total = await bookingCollection.countDocuments(query);

    res.json({
      success: true,
      bookings: bookingsWithCustomer,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / parseInt(limit)),
      },
    });
  } catch (error) {
    console.error("Error fetching provider bookings:", error);
    res.status(500).json({
      error: "Internal server error",
      message: "Unable to fetch bookings",
    });
  }
});

// Update booking status
app.put("/api/bookings/:bookingId/status", async (req, res) => {
  try {
    const { bookingId } = req.params;
    const { status, notes } = req.body;

    const validStatuses = [
      "pending",
      "confirmed",
      "in_progress",
      "completed",
      "cancelled",
    ];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({
        error: "Invalid status",
        message: "Status must be one of: " + validStatuses.join(", "),
      });
    }

    const updateData = {
      status,
      updatedAt: new Date(),
    };

    if (notes) {
      updateData.notes = notes;
    }

    const result = await bookingCollection.updateOne(
      { bookingId },
      { $set: updateData }
    );

    if (result.matchedCount === 0) {
      return res.status(404).json({
        error: "Booking not found",
        message: "The specified booking does not exist",
      });
    }

    // Get booking details for notifications
    const booking = await bookingCollection.findOne({ bookingId });
    if (booking) {
      // Send notification to customer
      await notificationCollection.insertOne({
        userId: booking.customerId,
        type: "booking_status_update",
        title: "Booking Status Updated",
        message: `Your booking (${bookingId}) status has been updated to ${status}.`,
        data: {
          bookingId,
          status,
          providerId: booking.providerId,
        },
        read: false,
        createdAt: new Date(),
      });
    }

    res.json({
      success: true,
      message: "Booking status updated successfully",
      bookingId,
      status,
    });
  } catch (error) {
    console.error("Error updating booking status:", error);
    res.status(500).json({
      error: "Internal server error",
      message: "Unable to update booking status",
    });
  }
});

// Get booking details
app.get("/api/bookings/:bookingId", async (req, res) => {
  try {
    const { bookingId } = req.params;

    const booking = await bookingCollection.findOne({ bookingId });
    if (!booking) {
      return res.status(404).json({
        error: "Booking not found",
        message: "The specified booking does not exist",
      });
    }

    // Get provider and customer details
    const [provider, customer] = await Promise.all([
      usersCollection.findOne(
        { uid: booking.providerId },
        {
          projection: {
            name: 1,
            businessName: 1,
            photoURL: 1,
            phone: 1,
            email: 1,
            address: 1,
          },
        }
      ),
      usersCollection.findOne(
        { uid: booking.customerId },
        { projection: { name: 1, email: 1, phone: 1, photoURL: 1 } }
      ),
    ]);

    res.json({
      success: true,
      booking: {
        ...booking,
        provider: provider || null,
        customer: customer || null,
      },
    });
  } catch (error) {
    console.error("Error fetching booking details:", error);
    res.status(500).json({
      error: "Internal server error",
      message: "Unable to fetch booking details",
    });
  }
});

// Cancel booking
app.put("/api/bookings/:bookingId/cancel", async (req, res) => {
  try {
    const { bookingId } = req.params;
    const { reason } = req.body;

    const booking = await bookingCollection.findOne({ bookingId });
    if (!booking) {
      return res.status(404).json({
        error: "Booking not found",
        message: "The specified booking does not exist",
      });
    }

    if (booking.status === "completed" || booking.status === "cancelled") {
      return res.status(400).json({
        error: "Invalid operation",
        message: "Cannot cancel a completed or already cancelled booking",
      });
    }

    // Update booking status
    await bookingCollection.updateOne(
      { bookingId },
      {
        $set: {
          status: "cancelled",
          cancellationReason: reason || "Cancelled by user",
          updatedAt: new Date(),
        },
      }
    );

    // Send notifications
    await Promise.all([
      notificationCollection.insertOne({
        userId: booking.customerId,
        type: "booking_cancelled",
        title: "Booking Cancelled",
        message: `Your booking (${bookingId}) has been cancelled.`,
        data: { bookingId, reason },
        read: false,
        createdAt: new Date(),
      }),
      notificationCollection.insertOne({
        userId: booking.providerId,
        type: "booking_cancelled",
        title: "Booking Cancelled",
        message: `Booking (${bookingId}) has been cancelled by the customer.`,
        data: { bookingId, reason, customerId: booking.customerId },
        read: false,
        createdAt: new Date(),
      }),
    ]);

    res.json({
      success: true,
      message: "Booking cancelled successfully",
      bookingId,
    });
  } catch (error) {
    console.error("Error cancelling booking:", error);
    res.status(500).json({
      error: "Internal server error",
      message: "Unable to cancel booking",
    });
  }
});

// Initiate payment for completed booking
app.post("/api/bookings/:bookingId/payment", async (req, res) => {
  try {
    const { bookingId } = req.params;
    const { paymentMethod = "online" } = req.body;

    // Find the booking
    const booking = await bookingCollection.findOne({ bookingId });
    if (!booking) {
      return res.status(404).json({
        success: false,
        error: "Booking not found",
        message: "The specified booking does not exist",
      });
    }

    // Validate booking status and payment status
    if (booking.status !== "completed") {
      return res.status(400).json({
        success: false,
        error: "Invalid booking status",
        message: "Payment can only be initiated for completed bookings",
      });
    }

    if (booking.paymentStatus === "paid") {
      return res.status(400).json({
        success: false,
        error: "Already paid",
        message: "This booking has already been paid",
      });
    }

    if (paymentMethod !== "online") {
      return res.status(400).json({
        success: false,
        error: "Invalid payment method",
        message: "Only online payment is supported",
      });
    }

    // Prepare SSL Commerz payment data
    const paymentData = {
      total_amount: booking.servicePrice,
      currency: "BDT",
      tran_id: bookingId,
      success_url: sslCommerzConfig.success_url,
      fail_url: sslCommerzConfig.fail_url,
      cancel_url: sslCommerzConfig.cancel_url,
      ipn_url: sslCommerzConfig.ipn_url,
      cus_name: booking.customerInfo?.name || "Customer",
      cus_email: booking.customerInfo?.email || "customer@example.com",
      cus_add1: booking.address,
      cus_city: "Dhaka",
      cus_country: "Bangladesh",
      cus_phone: booking.customerInfo?.phone || "01987654321",
      cus_postcode: "1000",
      shipping_method: "NO",
      product_name: booking.serviceName,
      product_category: "Service",
      product_profile: "general",
      multi_card_name:
        "brac_visa,mastercard,amex,dbbl_visa,mobilebanking,internetbanking",
      value_a: bookingId,
      value_b: booking.acceptedProviderId,
      value_c: booking.customerId,
      value_d: booking.serviceId,
    };

    // Initialize SSL Commerz payment
    const sslResponse = await sslcommerz.init(paymentData);

    if (sslResponse && sslResponse.status === "SUCCESS") {
      // Update booking with SSL session key
      await bookingCollection.updateOne(
        { bookingId },
        {
          $set: {
            sslSessionKey: sslResponse.sessionkey,
            paymentStatus: "pending",
            updatedAt: new Date(),
          },
        }
      );

      return res.json({
        success: true,
        message: "Payment initiated successfully. Please complete payment.",
        bookingId,
        paymentUrl: sslResponse.GatewayPageURL,
        sessionKey: sslResponse.sessionkey,
        redirectUrls: {
          success: `${sslCommerzConfig.success_url}?tran_id=${bookingId}&total_amount=${paymentData.total_amount}&currency=${paymentData.currency}&cus_name=${paymentData.cus_name}&cus_email=${paymentData.cus_email}`,
          fail: `${sslCommerzConfig.fail_url}?tran_id=${bookingId}&total_amount=${paymentData.total_amount}&currency=${paymentData.currency}`,
          cancel: `${sslCommerzConfig.cancel_url}?tran_id=${bookingId}&total_amount=${paymentData.total_amount}&currency=${paymentData.currency}`,
        },
      });
    }

    // SSL Commerz failed
    return res.status(400).json({
      success: false,
      message:
        "Payment gateway is temporarily unavailable. Please try again later.",
      error: "SSL_COMMERZ_FAILED",
      details: sslResponse?.failedreason || "SSL Commerz initialization failed",
    });
  } catch (error) {
    console.error("Error initiating payment:", error);
    res.status(500).json({
      success: false,
      error: "Internal server error",
      message: "Unable to initiate payment",
    });
  }
});

// SSL Commerz Success URL Handler (POST request)
app.post("/payment-success.html", async (req, res) => {
  try {
    const {
      tran_id,
      total_amount,
      currency,
      cus_name,
      cus_email,
      val_id,
      card_type,
      store_amount,
      bank_tran_id,
      status,
      tran_date,
    } = req.body;

    console.log("SSL Commerz Success Callback (POST):", req.body);

    // Update payment status in database
    if (tran_id && val_id) {
      try {
        const updateResult = await bookingCollection.updateOne(
          { bookingId: tran_id },
          {
            $set: {
              paymentStatus: "paid",
              sslValId: val_id,
              paymentAmount: total_amount || store_amount,
              paymentCurrency: currency,
              paymentStatusUpdate: status || "SUCCESS",
              bankTransactionId: bank_tran_id,
              paymentDate: tran_date ? new Date(tran_date) : new Date(),
              updatedAt: new Date(),
            },
          }
        );

        console.log("Payment status updated:", updateResult);
      } catch (dbError) {
        console.error("Database update error:", dbError);
      }
    }

    // Get booking details for service and provider info
    let serviceName = "Service Completed";
    let providerName = "Professional Provider";

    if (tran_id) {
      try {
        const booking = await bookingCollection.findOne({ bookingId: tran_id });
        if (booking) {
          serviceName = booking.serviceName || "Service Completed";
          providerName =
            booking.acceptedProviderName || "Professional Provider";
        }
      } catch (dbError) {
        console.error("Error fetching booking details:", dbError);
      }
    }

    // Redirect to success page with additional parameters
    const successParams = new URLSearchParams({
      ...req.body,
      service_name: serviceName,
      provider_name: providerName,
    });

    res.redirect(`/payment-success.html?${successParams.toString()}`);
  } catch (error) {
    console.error("Error handling payment success:", error);
    res.status(500).send("Payment success page error");
  }
});

// SSL Commerz Success URL Handler (GET request - for direct access)
app.get("/payment-success.html", async (req, res) => {
  try {
    const {
      tran_id,
      total_amount,
      currency,
      cus_name,
      cus_email,
      val_id,
      card_type,
      store_amount,
      bank_tran_id,
      status,
      tran_date,
    } = req.query;

    console.log("SSL Commerz Success Callback:", req.query);

    // Update payment status in database
    if (tran_id && val_id) {
      try {
        const updateResult = await bookingCollection.updateOne(
          { bookingId: tran_id },
          {
            $set: {
              paymentStatus: "paid",
              sslValId: val_id,
              paymentAmount: total_amount || store_amount,
              paymentCurrency: currency,
              paymentStatusUpdate: status || "SUCCESS",
              bankTransactionId: bank_tran_id,
              paymentDate: tran_date ? new Date(tran_date) : new Date(),
              updatedAt: new Date(),
            },
          }
        );

        console.log("Payment status updated:", updateResult);
      } catch (dbError) {
        console.error("Database update error:", dbError);
      }
    }

    // Serve the success page
    res.sendFile(path.join(__dirname, "public", "payment-success.html"));
  } catch (error) {
    console.error("Error handling payment success:", error);
    res.status(500).send("Payment success page error");
  }
});

// Test POST payment success endpoint
app.post("/test-payment-success-post", (req, res) => {
  const testData = {
    tran_id: "TEST-POST-12345",
    total_amount: "750",
    currency: "BDT",
    cus_name: "Test Customer POST",
    cus_email: "testpost@example.com",
    val_id: "TEST-POST-VAL-123",
    card_type: "VISA",
    status: "SUCCESS",
    bank_tran_id: "BANK-TEST-123",
  };

  // Simulate POST request to payment success endpoint
  req.body = testData;
  req.query = testData;

  // Call the actual success handler
  res.redirect(
    `/payment-success.html?${new URLSearchParams(testData).toString()}`
  );
});

// Test backend order success page
app.get("/test-payment-success", (req, res) => {
  const testParams = new URLSearchParams({
    tran_id: "BK-TEST-12345",
    total_amount: "2500",
    currency: "BDT",
    cus_name: "Test Customer",
    cus_email: "test@example.com",
    service_name: "Home Cleaning Service",
    provider_name: "Professional Cleaners",
    val_id: "TEST-VAL-123",
    card_type: "VISA",
  });

  res.redirect(`/payment-success.html?${testParams.toString()}`);
});

// Test SSL Commerz connection
app.get("/api/test-ssl-commerz", async (req, res) => {
  try {
    const testPaymentData = {
      total_amount: 100,
      currency: "BDT",
      tran_id: `TEST-${Date.now()}`,
      success_url: sslCommerzConfig.success_url,
      fail_url: sslCommerzConfig.fail_url,
      cancel_url: sslCommerzConfig.cancel_url,
      ipn_url: sslCommerzConfig.ipn_url,
      cus_name: "Test Customer",
      cus_email: "test@example.com",
      cus_add1: "Test Address",
      cus_city: "Dhaka",
      cus_country: "Bangladesh",
      cus_phone: "01987654321",
      cus_postcode: "1000",
      shipping_method: "NO",
      product_name: "Test Service",
      product_category: "Service",
      product_profile: "general",
    };

    const sslResponse = await sslcommerz.init(testPaymentData);

    res.json({
      success: true,
      message: "SSL Commerz connection test completed",
      config: {
        store_id: sslCommerzConfig.store_id,
        is_live: sslCommerzConfig.is_live,
        environment: isProduction ? "production" : "development",
      },
      response: sslResponse,
    });
  } catch (error) {
    console.error("SSL Commerz test failed:", error);
    res.status(500).json({
      success: false,
      message: "SSL Commerz connection test failed",
      error: error.message,
    });
  }
});

app.post("/api/bookings/broadcast", async (req, res) => {
  try {
    const {
      customerId,
      serviceId,
      serviceName,
      servicePrice,
      address,
      bookingDate,
      bookingTime,
      specialInstructions,
      contactInfo,
    } = req.body;

    // Validate required fields
    if (
      !customerId ||
      !serviceId ||
      !serviceName ||
      !servicePrice ||
      !address ||
      !bookingDate
    ) {
      return res.status(400).json({
        success: false,
        message: "Missing required booking information",
      });
    }

    // Generate unique booking ID
    const bookingId = `BK-${Math.random()
      .toString(36)
      .substr(2, 9)
      .toUpperCase()}-${Date.now().toString(36).substr(-4)}`;

    // Create booking record with broadcast status
    const booking = {
      bookingId,
      customerId,
      serviceId,
      serviceName,
      servicePrice: parseFloat(servicePrice),
      address,
      bookingDate: new Date(bookingDate),
      bookingTime,
      specialInstructions,
      contactInfo,
      status: "broadcast_pending", // New status for broadcast
      paymentStatus: "pending",
      broadcastStatus: "active", // Active broadcast
      acceptedProviderId: null,
      broadcastedAt: new Date(),
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    // Save booking to database
    const result = await bookingCollection.insertOne(booking);

    // Find relevant service providers based on service type and location
    const relevantProviders = await usersCollection
      .find({
        role: "provider",
        status: "approved",
        $or: [
          { services: { $in: [serviceName] } }, // Legacy field
          { serviceCategories: { $in: [serviceId] } }, // New field structure
          { myServices: { $elemMatch: { serviceName: serviceName } } }, // Provider's own services
        ],
        // Add location-based filtering if needed
      })
      .toArray();

    // Create broadcast notifications for each provider
    const broadcastNotifications = relevantProviders.map((provider) => ({
      userId: provider.uid,
      type: "booking_broadcast",
      title: "New Booking Available",
      message: `New ${serviceName} booking available in your area. Amount: ৳${servicePrice}`,
      data: {
        bookingId,
        serviceName,
        servicePrice,
        address,
        bookingDate,
        bookingTime,
        broadcastExpiry: new Date(Date.now() + 30 * 60 * 1000), // 30 minutes expiry
      },
      read: false,
      createdAt: new Date(),
    }));

    // Insert notifications
    if (broadcastNotifications.length > 0) {
      await notificationCollection.insertMany(broadcastNotifications);
    }

    // Update booking with broadcast info
    await bookingCollection.updateOne(
      { bookingId },
      {
        $set: {
          broadcastedProviders: relevantProviders.map((p) => p.uid),
          broadcastExpiry: new Date(Date.now() + 30 * 60 * 1000), // 30 minutes expiry
        },
      }
    );

    res.json({
      success: true,
      message: "Booking created and broadcast to providers",
      data: {
        bookingId,
        broadcastedTo: relevantProviders.length,
        providers: relevantProviders.map((p) => ({
          id: p.uid,
          name: p.businessName || p.name,
          rating: p.rating || 0,
        })),
      },
    });
  } catch (error) {
    console.error("Error creating booking broadcast:", error);
    res.status(500).json({
      success: false,
      message: "Failed to create booking broadcast",
    });
  }
});

// Get available bookings for providers with filters
app.get("/api/provider/bookings/available", async (req, res) => {
  try {
    const {
      serviceCategory,
      division,
      district,
      upazilla,
      page = 1,
      limit = 10,
    } = req.query;

    const query = {
      status: "broadcast_pending",
      broadcastStatus: "active",
      broadcastExpiry: { $gt: new Date() }, // Not expired
    };

    // Add service category filter if provided
    if (serviceCategory) {
      query.serviceId = serviceCategory;
    }

    // Add location filters if provided
    if (division) {
      query["serviceArea.division"] = division;
    }
    if (district) {
      query["serviceArea.district"] = district;
    }
    if (upazilla) {
      query["serviceArea.upazilla"] = upazilla;
    }

    const skip = (parseInt(page) - 1) * parseInt(limit);

    console.log("Available bookings query:", query);

    const bookings = await bookingCollection
      .find(query)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit))
      .toArray();

    console.log("Found available bookings:", bookings.length);
    if (bookings.length > 0) {
      console.log("Sample booking:", {
        bookingId: bookings[0].bookingId,
        status: bookings[0].status,
        broadcastStatus: bookings[0].broadcastStatus,
        broadcastExpiry: bookings[0].broadcastExpiry,
      });
    }

    const totalCount = await bookingCollection.countDocuments(query);

    res.json({
      success: true,
      bookings,
      pagination: {
        currentPage: parseInt(page),
        totalPages: Math.ceil(totalCount / parseInt(limit)),
        totalCount,
        hasNext: skip + bookings.length < totalCount,
        hasPrev: parseInt(page) > 1,
      },
    });
  } catch (error) {
    console.error("Error fetching available bookings:", error);
    res.status(500).json({
      success: false,
      message: "Failed to fetch available bookings",
    });
  }
});

// Provider accepts booking
app.post("/api/bookings/:bookingId/accept", async (req, res) => {
  try {
    const { bookingId } = req.params;
    const { providerId } = req.body;

    console.log("Accept booking request:", { bookingId, providerId });
    console.log("Provider ID type:", typeof providerId);
    console.log("Provider ID value:", providerId);

    if (!providerId) {
      console.log("Error: Provider ID is required");
      return res.status(400).json({
        success: false,
        message: "Provider ID is required",
        error: "MISSING_PROVIDER_ID",
      });
    }

    // Find the booking
    const booking = await bookingCollection.findOne({ bookingId });
    if (!booking) {
      console.log("Error: Booking not found:", bookingId);
      return res.status(404).json({
        success: false,
        message: "Booking not found",
        error: "BOOKING_NOT_FOUND",
      });
    }

    // Check if booking is still available for acceptance

    // Temporary: Allow any booking status for testing
    if (booking.status === "expired" || booking.acceptedProviderId) {
      console.log("Booking already accepted or expired:", {
        status: booking.status,
        acceptedProviderId: booking.acceptedProviderId,
      });
      return res.status(400).json({
        success: false,
        message: "Booking is no longer available for acceptance",
        error: "BOOKING_UNAVAILABLE",
      });
    }

    if (
      booking.status !== "broadcast_pending" ||
      booking.broadcastStatus !== "active"
    ) {
      // Temporary: Allow non-broadcast bookings for testing
    }

    // Check if broadcast hasn't expired
    if (booking.broadcastExpiry && new Date() > booking.broadcastExpiry) {
      // Mark broadcast as expired
      await bookingCollection.updateOne(
        { bookingId },
        {
          $set: {
            broadcastStatus: "expired",
            status: "expired",
            updatedAt: new Date(),
          },
        }
      );

      return res.status(400).json({
        success: false,
        message: "Booking broadcast has expired",
        error: "BOOKING_EXPIRED",
      });
    }

    // Get provider details from providers collection
    // Try multiple ways to find the provider
    let provider = null;

    // First try by uid (if it exists)
    provider = await providersCollection.findOne({ uid: providerId });

    // If not found by uid, try by email (since providerId might be email)
    if (!provider && providerId.includes("@")) {
      provider = await providersCollection.findOne({ email: providerId });
    }

    // If still not found, try by _id (ObjectId)
    if (!provider) {
      try {
        provider = await providersCollection.findOne({
          _id: new ObjectId(providerId),
        });
      } catch (error) {
        // providerId is not a valid ObjectId, continue
      }
    }

    if (!provider) {
      console.log("Provider not found with any method:", providerId);
      return res.status(404).json({
        success: false,
        message:
          "Provider not found. Please ensure you are logged in as a registered provider.",
        error: "PROVIDER_NOT_FOUND",
      });
    }

    console.log("Provider found:", {
      _id: provider._id,
      uid: provider.uid,
      email: provider.email,
      status: provider.status,
      businessName: provider.businessName,
    });

    // Check if provider is active and approved
    if (provider.status !== "approved") {
      console.log("Provider status check failed:", {
        providerId,
        status: provider.status,
        businessName: provider.businessName,
      });

      // Temporary: Allow pending providers for testing
      if (provider.status === "pending") {
        console.log("Allowing pending provider for testing");
      } else {
        return res.status(400).json({
          success: false,
          message: "Provider account is not active or approved",
        });
      }
    }

    // Check if provider offers this service (more flexible check)
    const service = await servicesCollection.findOne({
      _id: new ObjectId(booking.serviceId),
    });

    let providerEligible = false;

    // Check multiple ways provider might offer this service
    if (service) {
      // Check if provider has this service category
      if (
        provider.serviceCategories &&
        provider.serviceCategories.includes(service.category)
      ) {
        providerEligible = true;
        console.log("Provider eligible: service category match");
      }
      // Check if provider has this specific service
      else if (
        provider.services &&
        provider.services.includes(booking.serviceName)
      ) {
        providerEligible = true;
        console.log("Provider eligible: service name match");
      }
      // Check if provider has this service in their myServices
      else if (
        provider.myServices &&
        provider.myServices.some((s) => s.serviceName === booking.serviceName)
      ) {
        providerEligible = true;
        console.log("Provider eligible: myServices match");
      }
      // Check if provider was in the original broadcast list
      else if (
        booking.broadcastedProviders &&
        booking.broadcastedProviders.includes(providerId)
      ) {
        providerEligible = true;
        console.log("Provider eligible: in broadcast list");
      }
    }

    // Temporary fallback: Allow any approved or pending provider to accept any booking
    if (
      !providerEligible &&
      (provider.status === "approved" || provider.status === "pending")
    ) {
      providerEligible = true;
      console.log("Provider eligible: approved/pending provider fallback");
    }

    console.log("Provider eligibility result:", providerEligible);

    if (!providerEligible) {
      return res.status(400).json({
        success: false,
        message: "Provider was not eligible for this booking",
        error: "PROVIDER_NOT_ELIGIBLE",
      });
    }

    // Accept the booking (first-come-first-served)
    // Temporary: More flexible update query for testing
    const updateResult = await bookingCollection.updateOne(
      {
        bookingId,
        acceptedProviderId: null, // Ensure no one else has accepted
      },
      {
        $set: {
          status: "pending", // Change to normal pending status
          acceptedProviderId: providerId,
          acceptedAt: new Date(),
          broadcastStatus: "accepted",
          updatedAt: new Date(),
          // Add provider acceptance information
          providerAcceptanceInfo: {
            providerId: providerId,
            providerName:
              provider.businessName || provider.name || "Service Provider",
            providerEmail: provider.email,
            providerPhone: provider.phone,
            providerAddress: provider.address,
            acceptedAt: new Date(),
            providerStatus: provider.status,
            providerRating: provider.rating || 0,
            providerExperience: provider.experience || "Not specified",
            providerSpecialization: provider.specialization || [],
          },
        },
      }
    );

    if (updateResult.modifiedCount === 0) {
      return res.status(409).json({
        success: false,
        message: "Booking has already been accepted by another provider",
        error: "BOOKING_ALREADY_ACCEPTED",
      });
    }

    // Provider details already fetched above

    // Notify customer about acceptance
    await notificationCollection.insertOne({
      userId: booking.customerId,
      type: "booking_accepted",
      title: "Booking Accepted",
      message: `Your booking has been accepted by ${
        provider?.businessName || provider?.name
      }`,
      data: {
        bookingId,
        providerId,
        providerName: provider?.businessName || provider?.name,
        providerPhone: provider?.phone,
      },
      read: false,
      createdAt: new Date(),
    });

    // Notify other providers that booking is no longer available
    const otherProviders = booking.broadcastedProviders.filter(
      (id) => id !== providerId
    );
    if (otherProviders.length > 0) {
      const rejectionNotifications = otherProviders.map((providerId) => ({
        userId: providerId,
        type: "booking_taken",
        title: "Booking No Longer Available",
        message: `The ${booking.serviceName} booking has been accepted by another provider`,
        data: {
          bookingId,
          serviceName: booking.serviceName,
        },
        read: false,
        createdAt: new Date(),
      }));

      await notificationCollection.insertMany(rejectionNotifications);
    }

    res.json({
      success: true,
      message: "Booking accepted successfully",
      data: {
        bookingId,
        providerId,
        providerName: provider?.businessName || provider?.name,
        acceptedAt: new Date(),
      },
    });
  } catch (error) {
    console.error("Error accepting booking:", error);
    console.error("Error details:", {
      message: error.message,
      stack: error.stack,
      name: error.name,
    });
    res.status(500).json({
      success: false,
      message: "Failed to accept booking",
      error: error.message,
    });
  }
});

// Get provider's accepted bookings
app.get("/api/provider/bookings/accepted", async (req, res) => {
  try {
    const { providerId, page = 1, limit = 10 } = req.query;

    if (!providerId) {
      return res.status(400).json({
        success: false,
        message: "Provider ID is required",
      });
    }

    const skip = (parseInt(page) - 1) * parseInt(limit);

    const query = {
      acceptedProviderId: providerId,
      status: { $in: ["pending", "confirmed", "in_progress", "completed"] },
    };

    const bookings = await bookingCollection
      .find(query)
      .sort({ acceptedAt: -1 })
      .skip(skip)
      .limit(parseInt(limit))
      .toArray();

    const totalCount = await bookingCollection.countDocuments(query);

    // Get customer details for each booking
    const bookingsWithDetails = await Promise.all(
      bookings.map(async (booking) => {
        // Use existing customerInfo from booking, or fetch from users collection as fallback
        let customerInfo = booking.customerInfo;

        if (!customerInfo || !customerInfo.name) {
          const customer = await usersCollection.findOne(
            { uid: booking.customerId },
            { projection: { name: 1, email: 1, phone: 1, photoURL: 1 } }
          );
          customerInfo = customer;
        }

        console.log("Booking customer info:", {
          bookingId: booking.bookingId,
          originalCustomerInfo: booking.customerInfo,
          finalCustomerInfo: customerInfo,
        });

        return {
          ...booking,
          customerInfo: customerInfo,
        };
      })
    );

    res.json({
      success: true,
      bookings: bookingsWithDetails,
      pagination: {
        currentPage: parseInt(page),
        totalPages: Math.ceil(totalCount / parseInt(limit)),
        totalCount,
        hasNext: skip + bookings.length < totalCount,
        hasPrev: parseInt(page) > 1,
      },
    });
  } catch (error) {
    console.error("Error fetching accepted bookings:", error);
    res.status(500).json({
      success: false,
      message: "Failed to fetch accepted bookings",
    });
  }
});

// Update booking status (for provider)
app.put("/api/provider/bookings/:bookingId/status", async (req, res) => {
  try {
    const { bookingId } = req.params;
    const { providerId, status, notes } = req.body;

    if (!providerId || !status) {
      return res.status(400).json({
        success: false,
        message: "Provider ID and status are required",
      });
    }

    // Validate status
    const validStatuses = [
      "pending",
      "confirmed",
      "in_progress",
      "completed",
      "cancelled",
    ];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({
        success: false,
        message: "Invalid status",
      });
    }

    // Check if booking exists and belongs to provider
    const booking = await bookingCollection.findOne({
      bookingId,
      acceptedProviderId: providerId,
    });

    if (!booking) {
      return res.status(404).json({
        success: false,
        message: "Booking not found or not assigned to this provider",
      });
    }

    // Update booking status
    const updateResult = await bookingCollection.updateOne(
      { bookingId },
      {
        $set: {
          status,
          updatedAt: new Date(),
          ...(notes && { providerNotes: notes }),
        },
      }
    );

    if (updateResult.modifiedCount === 0) {
      return res.status(400).json({
        success: false,
        message: "Failed to update booking status",
      });
    }

    // Notify customer about status change
    await notificationCollection.insertOne({
      userId: booking.customerId,
      type: "booking_status_update",
      title: "Booking Status Updated",
      message: `Your booking status has been updated to ${status}`,
      data: {
        bookingId,
        status,
        providerId,
        providerNotes: notes,
      },
      read: false,
      createdAt: new Date(),
    });

    res.json({
      success: true,
      message: "Booking status updated successfully",
      data: {
        bookingId,
        status,
        updatedAt: new Date(),
      },
    });
  } catch (error) {
    console.error("Error updating booking status:", error);
    res.status(500).json({
      success: false,
      message: "Failed to update booking status",
    });
  }
});

// Debug endpoint to check provider eligibility for a booking
app.get(
  "/api/debug/provider-eligibility/:bookingId/:providerId",
  async (req, res) => {
    try {
      const { bookingId, providerId } = req.params;

      const booking = await bookingCollection.findOne({ bookingId });
      if (!booking) {
        return res.status(404).json({
          success: false,
          message: "Booking not found",
        });
      }

      // Try multiple ways to find the provider
      let provider = null;

      // First try by uid (if it exists)
      provider = await providersCollection.findOne({ uid: providerId });

      // If not found by uid, try by email (since providerId might be email)
      if (!provider && providerId.includes("@")) {
        provider = await providersCollection.findOne({ email: providerId });
      }

      // If still not found, try by _id (ObjectId)
      if (!provider) {
        try {
          provider = await providersCollection.findOne({
            _id: new ObjectId(providerId),
          });
        } catch (error) {
          // providerId is not a valid ObjectId, continue
        }
      }

      if (!provider) {
        return res.status(404).json({
          success: false,
          message: "Provider not found",
        });
      }

      const service = await servicesCollection.findOne({
        _id: new ObjectId(booking.serviceId),
      });

      const debugInfo = {
        booking: {
          bookingId: booking.bookingId,
          serviceName: booking.serviceName,
          serviceId: booking.serviceId,
          broadcastedProviders: booking.broadcastedProviders,
          status: booking.status,
          broadcastStatus: booking.broadcastStatus,
        },
        provider: {
          uid: provider.uid,
          status: provider.status,
          serviceCategories: provider.serviceCategories,
          services: provider.services,
          myServices: provider.myServices,
        },
        service: service
          ? {
              _id: service._id,
              serviceName: service.serviceName,
              category: service.category,
            }
          : null,
        eligibility: {
          isApproved: provider.status === "approved",
          isProvider: provider.role === "provider",
          hasServiceCategory:
            service &&
            provider.serviceCategories &&
            provider.serviceCategories.includes(service.category),
          hasService:
            provider.services &&
            provider.services.includes(booking.serviceName),
          hasMyService:
            provider.myServices &&
            provider.myServices.some(
              (s) => s.serviceName === booking.serviceName
            ),
          inBroadcastList:
            booking.broadcastedProviders &&
            booking.broadcastedProviders.includes(providerId),
        },
      };

      res.json({
        success: true,
        debug: debugInfo,
      });
    } catch (error) {
      console.error("Error checking provider eligibility:", error);
      res.status(500).json({
        success: false,
        message: "Failed to check provider eligibility",
        error: error.message,
      });
    }
  }
);

// Temporary endpoint to make provider eligible for any booking (for testing)
app.post("/api/debug/make-provider-eligible/:providerId", async (req, res) => {
  try {
    const { providerId } = req.params;
    const { serviceCategories = ["all"] } = req.body;

    const provider = await providersCollection.findOne({ uid: providerId });
    if (!provider) {
      return res.status(404).json({
        success: false,
        message: "Provider not found",
      });
    }

    // Update provider with service categories and ensure they're approved
    await providersCollection.updateOne(
      { uid: providerId },
      {
        $set: {
          serviceCategories: serviceCategories,
          services: ["Deep House Cleaning", "General Cleaning", "All Services"], // Add common services
          status: "approved",
          updatedAt: new Date(),
        },
      }
    );

    res.json({
      success: true,
      message: "Provider eligibility updated",
      provider: {
        uid: providerId,
        serviceCategories: serviceCategories,
        services: ["Deep House Cleaning", "General Cleaning", "All Services"],
        status: "approved",
      },
    });
  } catch (error) {
    console.error("Error updating provider eligibility:", error);
    res.status(500).json({
      success: false,
      message: "Failed to update provider eligibility",
      error: error.message,
    });
  }
});

// Get available broadcasts for a provider
app.get("/api/provider/broadcasts", async (req, res) => {
  try {
    const { providerId } = req.query;

    if (!providerId) {
      return res.status(400).json({
        success: false,
        message: "Provider ID is required",
      });
    }

    // Get provider details
    const provider = await usersCollection.findOne({ uid: providerId });
    if (!provider) {
      return res.status(404).json({
        success: false,
        message: "Provider not found",
      });
    }

    // Find active broadcasts for this provider's services
    const activeBroadcasts = await bookingCollection
      .find({
        status: "broadcast_pending",
        broadcastStatus: "active",
        broadcastedProviders: providerId,
        broadcastExpiry: { $gt: new Date() }, // Not expired
      })
      .sort({ broadcastedAt: -1 })
      .toArray();

    // Get customer details for each booking
    const broadcastsWithDetails = await Promise.all(
      activeBroadcasts.map(async (booking) => {
        const customer = await usersCollection.findOne(
          { uid: booking.customerId },
          { projection: { name: 1, email: 1, phone: 1 } }
        );

        return {
          ...booking,
          customerInfo: customer,
        };
      })
    );

    res.json({
      success: true,
      data: {
        broadcasts: broadcastsWithDetails,
        count: broadcastsWithDetails.length,
      },
    });
  } catch (error) {
    console.error("Error fetching provider broadcasts:", error);
    res.status(500).json({
      success: false,
      message: "Failed to fetch broadcasts",
    });
  }
});

// ==================== PROVIDER PROFILE MANAGEMENT ====================

// Middleware to verify provider authentication
const verifyProvider = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({
        success: false,
        error: "No token provided",
      });
    }

    const idToken = authHeader.split(" ")[1];

    // Verify Firebase ID token
    const decodedToken = await admin.auth().verifyIdToken(idToken);

    // Find provider by email (since that's how they're stored)
    const provider = await providersCollection.findOne({
      email: decodedToken.email,
    });

    if (!provider) {
      return res.status(403).json({
        success: false,
        error: "Provider access required",
      });
    }

    req.provider = provider;
    req.providerId = provider._id;
    req.providerEmail = provider.email;
    next();
  } catch (error) {
    console.error("Provider verification error:", error);
    res.status(401).json({
      success: false,
      error: "Invalid token",
    });
  }
};

// Get provider profile
app.get("/api/provider/profile", verifyProvider, async (req, res) => {
  try {
    const provider = req.provider;

    // Get service names from categories
    let serviceNames = [];
    if (provider.serviceCategories && provider.serviceCategories.length > 0) {
      // Filter out non-ObjectId strings and convert valid ObjectIds
      const validObjectIds = provider.serviceCategories
        .filter((id) => {
          try {
            new ObjectId(id);
            return true;
          } catch (error) {
            return false;
          }
        })
        .map((id) => new ObjectId(id));

      if (validObjectIds.length > 0) {
        const categories = await categoriesCollection
          .find({
            _id: { $in: validObjectIds },
          })
          .toArray();
        serviceNames = categories.map((cat) => cat.name);
      }

      // If no valid ObjectIds found, use the serviceCategories as service names directly
      if (serviceNames.length === 0 && provider.serviceCategories.length > 0) {
        serviceNames = provider.serviceCategories;
      }
    }

    // Calculate booking statistics
    const totalBookings = await bookingCollection.countDocuments({
      providerId: provider._id.toString(),
    });

    const completedBookings = await bookingCollection.countDocuments({
      providerId: provider._id.toString(),
      status: "completed",
    });

    // Calculate earnings (assuming each completed booking has a price)
    const completedBookingDocs = await bookingCollection
      .find({
        providerId: provider._id.toString(),
        status: "completed",
      })
      .toArray();

    const earnings = completedBookingDocs.reduce((total, booking) => {
      return total + (booking.price || 0);
    }, 0);

    // Calculate rating from reviews
    const reviews = await bookingCollection
      .find({
        providerId: provider._id.toString(),
        review: { $exists: true, $ne: null },
      })
      .toArray();

    const rating =
      reviews.length > 0
        ? reviews.reduce((sum, review) => sum + (review.rating || 0), 0) /
          reviews.length
        : 0;

    const profileData = {
      businessName:
        provider.businessName ||
        provider.companyName ||
        provider.fullName ||
        "",
      email: provider.email || "",
      phone: provider.phone || "",
      businessAddress:
        provider.address?.fullAddress || provider.address?.address || "",
      bio: provider.bio || provider.description || "",
      services: provider.serviceCategories || [],
      serviceNames: serviceNames,
      rating: Math.round(rating * 10) / 10, // Round to 1 decimal place
      totalBookings: totalBookings,
      completedBookings: completedBookings,
      earnings: earnings,
      experience: provider.experience || 0,
      skills: provider.skills || [],
      workingHours: provider.workingHours || "",
      workingDays: provider.workingDays || [],
      emergencyService: provider.emergencyService || false,
      status: provider.status || "pending",
      createdAt: provider.createdAt,
      updatedAt: provider.updatedAt,
    };

    res.json({
      success: true,
      data: profileData,
    });
  } catch (error) {
    console.error("Error fetching provider profile:", error);
    res.status(500).json({
      success: false,
      error: "Internal Server Error",
      message: "Failed to fetch provider profile",
    });
  }
});

// Update provider profile
app.put("/api/provider/profile", verifyProvider, async (req, res) => {
  try {
    const providerId = req.providerId;
    const updateData = req.body;

    // Remove fields that shouldn't be updated directly
    const allowedFields = [
      "businessName",
      "phone",
      "businessAddress",
      "bio",
      "experience",
      "skills",
      "workingHours",
      "workingDays",
      "emergencyService",
    ];

    const filteredData = {};
    allowedFields.forEach((field) => {
      if (updateData[field] !== undefined) {
        filteredData[field] = updateData[field];
      }
    });

    // Update address if businessAddress is provided
    if (updateData.businessAddress) {
      filteredData["address.fullAddress"] = updateData.businessAddress;
    }

    filteredData.updatedAt = new Date();

    const result = await providersCollection.updateOne(
      { _id: providerId },
      { $set: filteredData }
    );

    if (result.matchedCount === 0) {
      return res.status(404).json({
        success: false,
        error: "Provider not found",
      });
    }

    // Fetch updated provider data
    const updatedProvider = await providersCollection.findOne({
      _id: providerId,
    });

    // Get service names
    let serviceNames = [];
    if (
      updatedProvider.serviceCategories &&
      updatedProvider.serviceCategories.length > 0
    ) {
      // Filter out non-ObjectId strings and convert valid ObjectIds
      const validObjectIds = updatedProvider.serviceCategories
        .filter((id) => {
          try {
            new ObjectId(id);
            return true;
          } catch (error) {
            return false;
          }
        })
        .map((id) => new ObjectId(id));

      if (validObjectIds.length > 0) {
        const categories = await categoriesCollection
          .find({
            _id: { $in: validObjectIds },
          })
          .toArray();
        serviceNames = categories.map((cat) => cat.name);
      }

      // If no valid ObjectIds found, use the serviceCategories as service names directly
      if (
        serviceNames.length === 0 &&
        updatedProvider.serviceCategories.length > 0
      ) {
        serviceNames = updatedProvider.serviceCategories;
      }
    }

    const profileData = {
      businessName:
        updatedProvider.businessName ||
        updatedProvider.companyName ||
        updatedProvider.fullName ||
        "",
      email: updatedProvider.email || "",
      phone: updatedProvider.phone || "",
      businessAddress:
        updatedProvider.address?.fullAddress ||
        updatedProvider.address?.address ||
        "",
      bio: updatedProvider.bio || updatedProvider.description || "",
      services: updatedProvider.serviceCategories || [],
      serviceNames: serviceNames,
      experience: updatedProvider.experience || 0,
      skills: updatedProvider.skills || [],
      workingHours: updatedProvider.workingHours || "",
      workingDays: updatedProvider.workingDays || [],
      emergencyService: updatedProvider.emergencyService || false,
      status: updatedProvider.status || "pending",
      updatedAt: updatedProvider.updatedAt,
    };

    res.json({
      success: true,
      data: profileData,
      message: "Profile updated successfully",
    });
  } catch (error) {
    console.error("Error updating provider profile:", error);
    res.status(500).json({
      success: false,
      error: "Internal Server Error",
      message: "Failed to update provider profile",
    });
  }
});

// ==================== ADMIN BOOKINGS & ORDERS MANAGEMENT ====================

// Get booking statistics for admin
app.get("/api/admin/bookings/stats", verifyAdmin, async (req, res) => {
  try {
    const totalBookings = await bookingCollection.estimatedDocumentCount();
    const completedBookings = await bookingCollection.countDocuments({
      status: "completed",
    });
    const pendingBookings = await bookingCollection.countDocuments({
      status: "pending",
    });
    const confirmedBookings = await bookingCollection.countDocuments({
      status: "confirmed",
    });
    const inProgressBookings = await bookingCollection.countDocuments({
      status: "in_progress",
    });
    const cancelledBookings = await bookingCollection.countDocuments({
      status: "cancelled",
    });

    // Calculate total revenue
    const revenueResult = await bookingCollection
      .aggregate([
        { $match: { paymentStatus: "paid", status: "completed" } },
        { $group: { _id: null, totalRevenue: { $sum: "$servicePrice" } } },
      ])
      .toArray();

    const totalRevenue =
      revenueResult.length > 0 ? revenueResult[0].totalRevenue : 0;

    // Calculate daily stats for the last 30 days
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

    const dailyStats = await bookingCollection
      .aggregate([
        {
          $match: {
            createdAt: { $gte: thirtyDaysAgo },
          },
        },
        {
          $group: {
            _id: {
              year: { $year: "$createdAt" },
              month: { $month: "$createdAt" },
              day: { $dayOfMonth: "$createdAt" },
            },
            bookings: { $sum: 1 },
            revenue: {
              $sum: {
                $cond: [
                  { $eq: ["$paymentStatus", "paid"] },
                  "$servicePrice",
                  0,
                ],
              },
            },
          },
        },
        { $sort: { "_id.year": 1, "_id.month": 1, "_id.day": 1 } },
      ])
      .toArray();

    res.json({
      success: true,
      stats: {
        totalBookings,
        completedBookings,
        pendingBookings,
        confirmedBookings,
        inProgressBookings,
        cancelledBookings,
        totalRevenue,
        dailyStats,
      },
    });
  } catch (error) {
    console.error("Error fetching booking stats:", error);
    res.status(500).json({
      error: "Internal server error",
      message: "Unable to fetch booking statistics",
    });
  }
});

// Get all bookings with advanced filtering and pagination for admin
app.get("/api/admin/bookings", verifyAdmin, async (req, res) => {
  try {
    const {
      page = 1,
      limit = 10,
      status,
      paymentStatus,
      search,
      sortBy = "createdAt",
      sortOrder = "desc",
      startDate,
      endDate,
      providerId,
      serviceType,
    } = req.query;

    const skip = (parseInt(page) - 1) * parseInt(limit);
    const query = {};

    // Build query filters
    if (status && status !== "all") {
      query.status = status;
    }

    if (paymentStatus && paymentStatus !== "all") {
      query.paymentStatus = paymentStatus;
    }

    if (startDate && endDate) {
      query.createdAt = {
        $gte: new Date(startDate),
        $lte: new Date(endDate),
      };
    }

    if (providerId) {
      query.providerId = providerId;
    }

    if (serviceType) {
      query.serviceName = { $regex: serviceType, $options: "i" };
    }

    // Search functionality
    if (search) {
      query.$or = [
        { bookingId: { $regex: search, $options: "i" } },
        { "customerInfo.name": { $regex: search, $options: "i" } },
        { "customerInfo.email": { $regex: search, $options: "i" } },
        { serviceName: { $regex: search, $options: "i" } },
        { address: { $regex: search, $options: "i" } },
      ];
    }

    // Build sort object
    const sort = {};
    sort[sortBy] = sortOrder === "desc" ? -1 : 1;

    // Get bookings with pagination
    const [bookings, totalCount] = await Promise.all([
      bookingCollection
        .find(query)
        .sort(sort)
        .skip(skip)
        .limit(parseInt(limit))
        .toArray(),
      bookingCollection.countDocuments(query),
    ]);

    // Get provider and customer details for each booking
    const enrichedBookings = await Promise.all(
      bookings.map(async (booking) => {
        const [provider, customer] = await Promise.all([
          usersCollection.findOne(
            { uid: booking.providerId },
            {
              projection: {
                name: 1,
                businessName: 1,
                email: 1,
                phone: 1,
                profileImage: 1,
              },
            }
          ),
          usersCollection.findOne(
            { uid: booking.customerId },
            { projection: { name: 1, email: 1, phone: 1, profileImage: 1 } }
          ),
        ]);

        return {
          ...booking,
          providerInfo: provider,
          customerInfo: customer,
        };
      })
    );

    const totalPages = Math.ceil(totalCount / parseInt(limit));

    res.json({
      success: true,
      data: {
        bookings: enrichedBookings,
        pagination: {
          currentPage: parseInt(page),
          totalPages,
          totalCount,
          hasNext: parseInt(page) < totalPages,
          hasPrev: parseInt(page) > 1,
        },
      },
    });
  } catch (error) {
    console.error("Error fetching admin bookings:", error);
    res.status(500).json({
      success: false,
      error: "Internal server error",
      message: "Unable to fetch bookings",
    });
  }
});

// Get all users for admin management
app.get("/api/admin/users", verifyAdmin, async (req, res) => {
  try {
    const {
      page = 1,
      limit = 10,
      role,
      search,
      sortBy = "signupDate",
      sortOrder = "desc",
      status,
    } = req.query;

    const skip = (parseInt(page) - 1) * parseInt(limit);
    const query = {};

    // Build query filters
    if (role && role !== "all") {
      query.role = role;
    }

    if (status && status !== "all") {
      query.status = status;
    }

    // Search functionality
    if (search) {
      query.$or = [
        { userName: { $regex: search, $options: "i" } },
        { email: { $regex: search, $options: "i" } },
        { displayName: { $regex: search, $options: "i" } },
        { uid: { $regex: search, $options: "i" } },
      ];
    }

    // Build sort object
    const sort = {};
    sort[sortBy] = sortOrder === "desc" ? -1 : 1;

    // Get users with pagination
    const [users, totalCount] = await Promise.all([
      usersCollection
        .find(query)
        .sort(sort)
        .skip(skip)
        .limit(parseInt(limit))
        .toArray(),
      usersCollection.countDocuments(query),
    ]);

    // Get user statistics
    const stats = await Promise.all([
      usersCollection.countDocuments({ role: "user" }),
      usersCollection.countDocuments({ role: "provider" }),
      usersCollection.countDocuments({ role: "admin" }),
      usersCollection.countDocuments({ status: "Active" }),
      usersCollection.countDocuments({ status: "Inactive" }),
    ]);

    const userStats = {
      totalUsers: totalCount,
      regularUsers: stats[0],
      providers: stats[1],
      admins: stats[2],
      activeUsers: stats[3],
      inactiveUsers: stats[4],
    };

    res.json({
      success: true,
      data: {
        users: users.map((user) => ({
          uid: user.uid,
          userName: user.userName || user.displayName,
          email: user.email,
          phone: user.phone,
          photoURL: user.photoURL,
          role: user.role,
          status: user.status,
          signupDate: user.signupDate,
          lastLogin: user.lastLogin,
          serviceCategories: user.serviceCategories || [],
          services: user.services || [],
        })),
        pagination: {
          currentPage: parseInt(page),
          totalPages: Math.ceil(totalCount / parseInt(limit)),
          totalCount,
          limit: parseInt(limit),
        },
        stats: userStats,
      },
    });
  } catch (error) {
    console.error("Error fetching admin users:", error);
    res.status(500).json({
      success: false,
      error: "Internal server error",
      message: "Unable to fetch users",
    });
  }
});

// Update user role for admin
app.patch("/api/admin/users/:uid/role", verifyAdmin, async (req, res) => {
  try {
    const { uid } = req.params;
    const { role } = req.body;

    if (!role) {
      return res.status(400).json({
        success: false,
        error: "Role is required",
      });
    }

    const validRoles = ["user", "provider", "admin"];
    if (!validRoles.includes(role)) {
      return res.status(400).json({
        success: false,
        error: "Invalid role. Must be one of: user, provider, admin",
      });
    }

    const result = await usersCollection.updateOne(
      { uid },
      {
        $set: {
          role,
          updatedAt: new Date(),
        },
      }
    );

    if (result.matchedCount === 0) {
      return res.status(404).json({
        success: false,
        error: "User not found",
      });
    }

    res.json({
      success: true,
      message: "User role updated successfully",
      data: { uid, role },
    });
  } catch (error) {
    console.error("Error updating user role:", error);
    res.status(500).json({
      success: false,
      error: "Internal server error",
      message: "Unable to update user role",
    });
  }
});

// Update user status for admin
app.patch("/api/admin/users/:uid/status", verifyAdmin, async (req, res) => {
  try {
    const { uid } = req.params;
    const { status } = req.body;

    if (!status) {
      return res.status(400).json({
        success: false,
        error: "Status is required",
      });
    }

    const validStatuses = ["Active", "Inactive", "Suspended"];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({
        success: false,
        error: "Invalid status. Must be one of: Active, Inactive, Suspended",
      });
    }

    const result = await usersCollection.updateOne(
      { uid },
      {
        $set: {
          status,
          updatedAt: new Date(),
        },
      }
    );

    if (result.matchedCount === 0) {
      return res.status(404).json({
        success: false,
        error: "User not found",
      });
    }

    res.json({
      success: true,
      message: "User status updated successfully",
      data: { uid, status },
    });
  } catch (error) {
    console.error("Error updating user status:", error);
    res.status(500).json({
      success: false,
      error: "Internal server error",
      message: "Unable to update user status",
    });
  }
});

// Get single booking details for admin
app.get("/api/admin/bookings/:bookingId", verifyAdmin, async (req, res) => {
  try {
    const { bookingId } = req.params;

    const booking = await bookingCollection.findOne({ bookingId });
    if (!booking) {
      return res.status(404).json({
        success: false,
        message: "Booking not found",
      });
    }

    // Get provider and customer details
    const [provider, customer] = await Promise.all([
      usersCollection.findOne(
        { uid: booking.providerId },
        {
          projection: {
            name: 1,
            businessName: 1,
            email: 1,
            phone: 1,
            profileImage: 1,
            address: 1,
          },
        }
      ),
      usersCollection.findOne(
        { uid: booking.customerId },
        {
          projection: {
            name: 1,
            email: 1,
            phone: 1,
            profileImage: 1,
            address: 1,
          },
        }
      ),
    ]);

    // Get service details if serviceId exists
    let service = null;
    if (booking.serviceId) {
      service = await servicesCollection.findOne(
        { _id: new ObjectId(booking.serviceId) },
        {
          projection: {
            name: 1,
            description: 1,
            price: 1,
            category: 1,
            images: 1,
          },
        }
      );
    }

    res.json({
      success: true,
      data: {
        ...booking,
        providerInfo: provider,
        customerInfo: customer,
        serviceInfo: service,
      },
    });
  } catch (error) {
    console.error("Error fetching booking details:", error);
    res.status(500).json({
      success: false,
      error: "Internal server error",
      message: "Unable to fetch booking details",
    });
  }
});

// Update booking status (admin)
app.put(
  "/api/admin/bookings/:bookingId/status",
  verifyAdmin,
  async (req, res) => {
    try {
      const { bookingId } = req.params;
      const { status, notes } = req.body;

      const validStatuses = [
        "pending",
        "confirmed",
        "in_progress",
        "completed",
        "cancelled",
      ];
      if (!validStatuses.includes(status)) {
        return res.status(400).json({
          success: false,
          message:
            "Invalid status. Must be one of: " + validStatuses.join(", "),
        });
      }

      const booking = await bookingCollection.findOne({ bookingId });
      if (!booking) {
        return res.status(404).json({
          success: false,
          message: "Booking not found",
        });
      }

      // Update booking status
      const updateData = {
        status,
        updatedAt: new Date(),
      };

      if (notes) {
        updateData.adminNotes = notes;
      }

      // If status is completed, update payment status to paid if not already
      if (status === "completed" && booking.paymentStatus === "pending") {
        updateData.paymentStatus = "paid";
      }

      const result = await bookingCollection.updateOne(
        { bookingId },
        { $set: updateData }
      );

      if (result.modifiedCount === 0) {
        return res.status(400).json({
          success: false,
          message: "Failed to update booking status",
        });
      }

      // Send notification to customer
      await notificationCollection.insertOne({
        userId: booking.customerId,
        type: "booking_status_update",
        title: "Booking Status Updated",
        message: `Your booking (${bookingId}) status has been updated to ${status}.`,
        data: {
          bookingId,
          status,
          providerId: booking.providerId,
          adminUpdate: true,
        },
        read: false,
        createdAt: new Date(),
      });

      // Send notification to provider
      await notificationCollection.insertOne({
        userId: booking.providerId,
        type: "booking_status_update",
        title: "Booking Status Updated",
        message: `Booking (${bookingId}) status has been updated to ${status} by admin.`,
        data: {
          bookingId,
          status,
          customerId: booking.customerId,
          adminUpdate: true,
        },
        read: false,
        createdAt: new Date(),
      });

      res.json({
        success: true,
        message: "Booking status updated successfully",
        data: {
          bookingId,
          status,
          updatedAt: updateData.updatedAt,
        },
      });
    } catch (error) {
      console.error("Error updating booking status:", error);
      res.status(500).json({
        success: false,
        error: "Internal server error",
        message: "Unable to update booking status",
      });
    }
  }
);

// Bulk update booking statuses (admin)
app.put("/api/admin/bookings/bulk-status", verifyAdmin, async (req, res) => {
  try {
    const { bookingIds, status, notes } = req.body;

    if (!Array.isArray(bookingIds) || bookingIds.length === 0) {
      return res.status(400).json({
        success: false,
        message: "Booking IDs array is required",
      });
    }

    const validStatuses = [
      "pending",
      "confirmed",
      "in_progress",
      "completed",
      "cancelled",
    ];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({
        success: false,
        message: "Invalid status. Must be one of: " + validStatuses.join(", "),
      });
    }

    const updateData = {
      status,
      updatedAt: new Date(),
    };

    if (notes) {
      updateData.adminNotes = notes;
    }

    // If status is completed, update payment status to paid for pending payments
    if (status === "completed") {
      updateData.paymentStatus = "paid";
    }

    const result = await bookingCollection.updateMany(
      { bookingId: { $in: bookingIds } },
      { $set: updateData }
    );

    if (result.modifiedCount === 0) {
      return res.status(400).json({
        success: false,
        message: "No bookings were updated",
      });
    }

    // Send notifications to all affected users
    const bookings = await bookingCollection
      .find(
        { bookingId: { $in: bookingIds } },
        { projection: { bookingId: 1, customerId: 1, providerId: 1 } }
      )
      .toArray();

    const notifications = [];
    bookings.forEach((booking) => {
      notifications.push(
        {
          userId: booking.customerId,
          type: "booking_status_update",
          title: "Booking Status Updated",
          message: `Your booking (${booking.bookingId}) status has been updated to ${status}.`,
          data: {
            bookingId: booking.bookingId,
            status,
            providerId: booking.providerId,
            adminUpdate: true,
          },
          read: false,
          createdAt: new Date(),
        },
        {
          userId: booking.providerId,
          type: "booking_status_update",
          title: "Booking Status Updated",
          message: `Booking (${booking.bookingId}) status has been updated to ${status} by admin.`,
          data: {
            bookingId: booking.bookingId,
            status,
            customerId: booking.customerId,
            adminUpdate: true,
          },
          read: false,
          createdAt: new Date(),
        }
      );
    });

    if (notifications.length > 0) {
      await notificationCollection.insertMany(notifications);
    }

    res.json({
      success: true,
      message: `Successfully updated ${result.modifiedCount} bookings`,
      data: {
        updatedCount: result.modifiedCount,
        status,
        updatedAt: updateData.updatedAt,
      },
    });
  } catch (error) {
    console.error("Error bulk updating booking statuses:", error);
    res.status(500).json({
      success: false,
      error: "Internal server error",
      message: "Unable to bulk update booking statuses",
    });
  }
});

// Delete booking (admin)
app.delete("/api/admin/bookings/:bookingId", verifyAdmin, async (req, res) => {
  try {
    const { bookingId } = req.params;

    const booking = await bookingCollection.findOne({ bookingId });
    if (!booking) {
      return res.status(404).json({
        success: false,
        message: "Booking not found",
      });
    }

    // Only allow deletion of pending or cancelled bookings
    if (!["pending", "cancelled"].includes(booking.status)) {
      return res.status(400).json({
        success: false,
        message: "Only pending or cancelled bookings can be deleted",
      });
    }

    const result = await bookingCollection.deleteOne({ bookingId });

    if (result.deletedCount === 0) {
      return res.status(400).json({
        success: false,
        message: "Failed to delete booking",
      });
    }

    res.json({
      success: true,
      message: "Booking deleted successfully",
      data: {
        bookingId,
      },
    });
  } catch (error) {
    console.error("Error deleting booking:", error);
    res.status(500).json({
      success: false,
      error: "Internal server error",
      message: "Unable to delete booking",
    });
  }
});

// Export bookings data (admin)
app.get("/api/admin/bookings/export", verifyAdmin, async (req, res) => {
  try {
    const { format = "json", startDate, endDate, status } = req.query;

    const query = {};
    if (startDate && endDate) {
      query.createdAt = {
        $gte: new Date(startDate),
        $lte: new Date(endDate),
      };
    }
    if (status && status !== "all") {
      query.status = status;
    }

    const bookings = await bookingCollection.find(query).toArray();

    if (format === "csv") {
      // Generate CSV format
      const csvHeader =
        "Booking ID,Customer Name,Customer Email,Customer Phone,Provider Name,Service Name,Amount,Status,Payment Status,Booking Date,Service Date,Address\n";
      const csvRows = bookings
        .map(
          (booking) =>
            `"${booking.bookingId}","${booking.customerInfo?.name || ""}","${
              booking.customerInfo?.email || ""
            }","${booking.customerInfo?.phone || ""}","${
              booking.serviceName
            }","${booking.servicePrice}","${booking.status}","${
              booking.paymentStatus
            }","${booking.bookingDate}","${booking.address || ""}"`
        )
        .join("\n");

      res.setHeader("Content-Type", "text/csv");
      res.setHeader(
        "Content-Disposition",
        'attachment; filename="bookings.csv"'
      );
      res.send(csvHeader + csvRows);
    } else {
      // Return JSON format
      res.json({
        success: true,
        data: bookings,
        count: bookings.length,
        exportedAt: new Date(),
      });
    }
  } catch (error) {
    console.error("Error exporting bookings:", error);
    res.status(500).json({
      success: false,
      error: "Internal server error",
      message: "Unable to export bookings",
    });
  }
});

// Get booking analytics for admin dashboard
app.get("/api/admin/bookings/analytics", verifyAdmin, async (req, res) => {
  try {
    const { period = "30d" } = req.query;

    let startDate = new Date();
    switch (period) {
      case "7d":
        startDate.setDate(startDate.getDate() - 7);
        break;
      case "30d":
        startDate.setDate(startDate.getDate() - 30);
        break;
      case "90d":
        startDate.setDate(startDate.getDate() - 90);
        break;
      case "1y":
        startDate.setFullYear(startDate.getFullYear() - 1);
        break;
      default:
        startDate.setDate(startDate.getDate() - 30);
    }

    // Get booking trends
    const bookingTrends = await bookingCollection
      .aggregate([
        {
          $match: {
            createdAt: { $gte: startDate },
          },
        },
        {
          $group: {
            _id: {
              year: { $year: "$createdAt" },
              month: { $month: "$createdAt" },
              day: { $dayOfMonth: "$createdAt" },
            },
            bookings: { $sum: 1 },
            revenue: {
              $sum: {
                $cond: [
                  { $eq: ["$paymentStatus", "paid"] },
                  "$servicePrice",
                  0,
                ],
              },
            },
          },
        },
        { $sort: { "_id.year": 1, "_id.month": 1, "_id.day": 1 } },
      ])
      .toArray();

    // Get status distribution
    const statusDistribution = await bookingCollection
      .aggregate([
        {
          $match: {
            createdAt: { $gte: startDate },
          },
        },
        {
          $group: {
            _id: "$status",
            count: { $sum: 1 },
          },
        },
      ])
      .toArray();

    // Get service type distribution
    const serviceDistribution = await bookingCollection
      .aggregate([
        {
          $match: {
            createdAt: { $gte: startDate },
          },
        },
        {
          $group: {
            _id: "$serviceName",
            count: { $sum: 1 },
            revenue: {
              $sum: {
                $cond: [
                  { $eq: ["$paymentStatus", "paid"] },
                  "$servicePrice",
                  0,
                ],
              },
            },
          },
        },
        { $sort: { count: -1 } },
        { $limit: 10 },
      ])
      .toArray();

    // Get top providers
    const topProviders = await bookingCollection
      .aggregate([
        {
          $match: {
            createdAt: { $gte: startDate },
          },
        },
        {
          $group: {
            _id: "$providerId",
            bookings: { $sum: 1 },
            revenue: {
              $sum: {
                $cond: [
                  { $eq: ["$paymentStatus", "paid"] },
                  "$servicePrice",
                  0,
                ],
              },
            },
          },
        },
        { $sort: { bookings: -1 } },
        { $limit: 10 },
      ])
      .toArray();

    // Get provider names for top providers
    const providerIds = topProviders.map((p) => p._id);
    const providers = await usersCollection
      .find(
        { uid: { $in: providerIds } },
        { projection: { uid: 1, name: 1, businessName: 1 } }
      )
      .toArray();

    const enrichedTopProviders = topProviders.map((provider) => {
      const providerInfo = providers.find((p) => p.uid === provider._id);
      return {
        ...provider,
        providerName:
          providerInfo?.businessName || providerInfo?.name || "Unknown",
      };
    });

    res.json({
      success: true,
      data: {
        bookingTrends,
        statusDistribution,
        serviceDistribution,
        topProviders: enrichedTopProviders,
        period,
        startDate,
        endDate: new Date(),
      },
    });
  } catch (error) {
    console.error("Error fetching booking analytics:", error);
    res.status(500).json({
      success: false,
      error: "Internal server error",
      message: "Unable to fetch booking analytics",
    });
  }
});

// ==================== SERVICE PROVIDER MANAGEMENT APIs REMOVED ====================

// Provider endpoints removed

// Provider status update endpoint removed

// Provider update and stats endpoints removed

// Provider delete endpoint removed

// Sample provider data creation function removed

// Test endpoint removed

// ==================== PROVIDER REGISTRATION ENDPOINT ====================

// Provider Registration Endpoint
app.post("/provider-registration", async (req, res) => {
  const providersCollection = client
    .db("SubidhaHomeService")
    .collection("providers");

  try {
    const {
      uid,
      fullName,
      email,
      phone,
      businessName,
      businessType,
      businessAddress,
      city,
      district,
      postalCode,
      services,
      nidFront,
      nidBack,
      businessLicense,
      profilePhoto,
      serviceAreas,
      serviceDivision,
      serviceDistrict,
      serviceUpazilla,
      workingHours,
      workingDays,
      emergencyService,
      experience,
      skills,
      bio,
      status = "pending",
    } = req.body;

    // Check if provider already exists
    const existingProvider = await providersCollection.findOne({ uid });
    if (existingProvider) {
      return res.status(400).json({ error: "Provider already registered" });
    }

    // Check if email already exists
    const existingEmail = await providersCollection.findOne({ email });
    if (existingEmail) {
      return res.status(400).json({ error: "Email already registered" });
    }

    // Check if phone already exists
    const existingPhone = await providersCollection.findOne({ phone });
    if (existingPhone) {
      return res.status(400).json({ error: "Phone number already registered" });
    }

    // Create provider document
    const providerData = {
      uid,
      fullName,
      email,
      phone,
      businessName,
      businessType,
      businessAddress,
      city,
      district,
      postalCode,
      services,
      documents: {
        nidFront,
        nidBack,
        businessLicense,
        profilePhoto,
      },
      serviceAreas,
      serviceArea: {
        division: serviceDivision,
        district: serviceDistrict,
        upazilla: serviceUpazilla,
      },
      workingHours,
      workingDays,
      emergencyService,
      experience: parseInt(experience),
      skills,
      bio,
      status,
      rating: 0,
      totalBookings: 0,
      completedBookings: 0,
      earnings: 0,
      joinedDate: new Date(),
      lastActive: new Date(),
      isVerified: false,
      isActive: false,
    };

    // Insert provider
    const result = await providersCollection.insertOne(providerData);

    if (result.insertedId) {
      res.status(201).json({
        message: "Provider registration submitted successfully",
        providerId: result.insertedId,
        status: "pending",
      });
    } else {
      res.status(500).json({ error: "Failed to register provider" });
    }
  } catch (error) {
    console.error("Provider registration error:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// Get Pending Providers (Admin only)
app.get("/admin/pending-providers", verifyAdmin, async (req, res) => {
  const providersCollection = client
    .db("SubidhaHomeService")
    .collection("providers");

  try {
    const pendingProviders = await providersCollection
      .find({ status: "pending" })
      .sort({ joinedDate: -1 })
      .toArray();

    res.json({ providers: pendingProviders });
  } catch (error) {
    console.error("Error fetching pending providers:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// Approve/Reject Provider (Admin only)
app.put("/admin/provider/:id/status", verifyAdmin, async (req, res) => {
  const providersCollection = client
    .db("SubidhaHomeService")
    .collection("providers");

  try {
    const { status, reason } = req.body;
    const providerId = req.params.id;

    if (!["approved", "rejected"].includes(status)) {
      return res.status(400).json({ error: "Invalid status" });
    }

    const updateData = {
      status,
      isVerified: status === "approved",
      isActive: status === "approved",
      reviewedDate: new Date(),
      reviewReason: reason || "",
    };

    const result = await providersCollection.updateOne(
      { _id: new ObjectId(providerId) },
      { $set: updateData }
    );

    if (result.modifiedCount > 0) {
      res.json({ message: `Provider ${status} successfully` });
    } else {
      res.status(404).json({ error: "Provider not found" });
    }
  } catch (error) {
    console.error("Error updating provider status:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// Get all providers (admin only)
app.get("/admin/providers", verifyAdmin, async (req, res) => {
  const providersCollection = client
    .db("SubidhaHomeService")
    .collection("providers");

  try {
    const providers = await providersCollection.find({}).toArray();
    res.json({ providers });
  } catch (error) {
    console.error("Error fetching providers:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// Get providers by service and location
app.get("/providers/by-service/:serviceId", async (req, res) => {
  const providersCollection = client
    .db("SubidhaHomeService")
    .collection("providers");

  try {
    const { serviceId } = req.params;
    const { location } = req.query;

    console.log("🔍 Provider search request:", { serviceId, location });
    console.log("📋 ServiceId type:", typeof serviceId);

    // Validate serviceId
    if (!serviceId) {
      return res.status(400).json({ error: "Service ID is required" });
    }

    // First, get the service to find its category
    const servicesCollection = client
      .db("SubidhaHomeService")
      .collection("services");
    const service = await servicesCollection.findOne({
      _id: new ObjectId(serviceId),
    });

    if (!service) {
      console.log("❌ Service not found:", serviceId);
      return res.status(404).json({ error: "Service not found" });
    }

    console.log("🔍 Service found:", {
      serviceName: service.serviceName,
      category: service.category,
    });

    // Build query using category instead of service
    let query = {
      status: "approved",
      serviceCategories: { $in: [service.category] },
    };

    console.log("🔍 Initial query:", JSON.stringify(query, null, 2));
    console.log("🔍 Query field check:", {
      hasServiceCategories: query.serviceCategories ? "✅ YES" : "❌ NO",
      hasServices: query.services ? "✅ YES" : "❌ NO",
      serviceCategoriesValue: query.serviceCategories,
      servicesValue: query.services,
    });

    // Add location filter if provided
    if (location) {
      console.log("🎯 Location matching for:", location);

      // Normalize location for matching
      const normalizedLocation = location.toLowerCase().trim();
      console.log("🎯 Normalized location:", normalizedLocation);

      // Create multiple matching strategies
      const locationPatterns = [
        new RegExp(`^${normalizedLocation}$`, "i"), // Exact match
        new RegExp(`^${normalizedLocation}\\b`, "i"), // Starts with location
        new RegExp(`\\b${normalizedLocation}\\b`, "i"), // Word boundary match
        new RegExp(normalizedLocation.replace(/\s+/g, ".*"), "i"), // Flexible spacing
      ];

      // For "Dhaka" - also check for common variations
      if (normalizedLocation === "dhaka") {
        locationPatterns.push(
          new RegExp("dhaka", "i"),
          new RegExp("dacca", "i"), // Alternative spelling
          new RegExp("ঢাকা", "i") // Bengali spelling
        );
      }

      // Use $or to match any of the patterns in serviceAreas array
      query.$or = [
        { serviceAreas: { $in: locationPatterns } },
        { serviceAreas: { $regex: normalizedLocation, $options: "i" } },
        // Also check if any serviceArea contains the location
        {
          serviceAreas: {
            $elemMatch: { $regex: normalizedLocation, $options: "i" },
          },
        },
      ];

      console.log("📍 Location patterns:", locationPatterns);
      console.log("🔍 Final Query:", JSON.stringify(query, null, 2));
    } else {
      console.log("🌍 No location filter - returning all providers");
    }

    const providers = await providersCollection.find(query).toArray();

    // Debug: Check all providers in database
    const allProviders = await providersCollection.find({}).toArray();
    console.log("🔍 ALL PROVIDERS IN DATABASE:", allProviders.length);
    allProviders.forEach((p, index) => {
      console.log(`Provider ${index + 1}:`, {
        name: p.fullName || p.name,
        status: p.status,
        services: p.services,
        serviceCategories: p.serviceCategories,
        serviceAreas: p.serviceAreas,
        hasRequestedService: p.services?.includes(serviceId)
          ? "✅ YES"
          : "❌ NO",
        hasRequestedCategory: p.serviceCategories?.includes(service.category)
          ? "✅ YES"
          : "❌ NO",
      });
    });

    // Debug: Check if any provider has the requested service category
    const providersWithCategory = allProviders.filter((p) =>
      p.serviceCategories?.includes(service.category)
    );
    console.log(
      `🔍 Providers with category ${service.category}:`,
      providersWithCategory.length
    );
    providersWithCategory.forEach((p, index) => {
      console.log(`Category Provider ${index + 1}:`, {
        name: p.fullName || p.name,
        status: p.status,
        serviceAreas: p.serviceAreas,
        serviceCategories: p.serviceCategories,
      });
    });

    // Return real providers from database only
    console.log("📊 Returning real providers:", providers.length, "providers");
    console.log(
      "📊 Provider details:",
      providers.map((p) => ({
        name: p.fullName || p.name,
        status: p.status,
        services: p.services,
        serviceAreas: p.serviceAreas,
      }))
    );

    if (providers.length === 0) {
      console.log("⚠️ No providers found for this service and location");

      // Fallback: Try to find providers for the service without location filter
      console.log(
        "🔄 Trying fallback: providers for service without location filter"
      );
      const fallbackQuery = {
        status: "approved",
        serviceCategories: { $in: [service.category] },
      };

      const fallbackProviders = await providersCollection
        .find(fallbackQuery)
        .toArray();
      console.log("🔄 Fallback providers found:", fallbackProviders.length);

      if (fallbackProviders.length > 0) {
        console.log("✅ Returning fallback providers (service-based only)");
        return res.json({
          providers: fallbackProviders,
          fallback: true,
          message:
            "No providers found in your location, but providers available for this service",
        });
      }

      // Final fallback: Check if there are any approved providers at all
      console.log("🔄 Final fallback: checking for any approved providers");
      const anyProviders = await providersCollection
        .find({ status: "approved" })
        .toArray();
      console.log("🔄 Any approved providers found:", anyProviders.length);

      if (anyProviders.length > 0) {
        console.log(
          "⚠️ Found approved providers but none match the requested service"
        );
        return res.json({
          providers: [],
          fallback: true,
          message: `No providers found for this service. Found ${anyProviders.length} approved providers but none offer this service.`,
        });
      } else {
        console.log("❌ No approved providers found in database");
        return res.json({
          providers: [],
          fallback: true,
          message:
            "No approved providers found in the system. Please contact admin.",
        });
      }
    }

    res.json({ providers });
  } catch (error) {
    console.error("Error fetching providers by service:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// Booking API Endpoints
// Create a new booking
app.post("/api/bookings", async (req, res) => {
  const bookingsCollection = client
    .db("SubidhaHomeService")
    .collection("bookings");

  try {
    const bookingData = req.body;

    // Fetch service details to get the service photo if serviceId is provided
    let servicePhoto = null;
    if (bookingData.serviceId) {
      const service = await servicesCollection.findOne(
        { _id: new ObjectId(bookingData.serviceId) },
        { projection: { name: 1, image: 1, photoURL: 1 } }
      );
      servicePhoto = service?.image || service?.photoURL;
    }

    // Generate unique booking ID
    const bookingId = `BK${Date.now()}${Math.random()
      .toString(36)
      .substr(2, 5)
      .toUpperCase()}`;

    const booking = {
      ...bookingData,
      bookingId,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };

    const result = await bookingsCollection.insertOne(booking);

    console.log("✅ New booking created:", bookingId);
    res.status(201).json({
      success: true,
      bookingId,
      booking: booking,
    });
  } catch (error) {
    console.error("Error creating booking:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// Get booking details by ID
app.get("/api/bookings/:bookingId", async (req, res) => {
  const bookingsCollection = client
    .db("SubidhaHomeService")
    .collection("bookings");

  try {
    const { bookingId } = req.params;

    const booking = await bookingsCollection.findOne({ bookingId });

    if (!booking) {
      return res.status(404).json({ error: "Booking not found" });
    }

    res.json({ booking });
  } catch (error) {
    console.error("Error fetching booking:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// Update booking status
app.put("/api/bookings/:bookingId/status", async (req, res) => {
  const bookingsCollection = client
    .db("SubidhaHomeService")
    .collection("bookings");

  try {
    const { bookingId } = req.params;
    const { status, notes } = req.body;

    const updateData = {
      status,
      updatedAt: new Date().toISOString(),
    };

    if (notes) {
      updateData.notes = notes;
    }

    const result = await bookingsCollection.updateOne(
      { bookingId },
      { $set: updateData }
    );

    if (result.matchedCount === 0) {
      return res.status(404).json({ error: "Booking not found" });
    }

    console.log("✅ Booking status updated:", bookingId, "to", status);
    res.json({ success: true, message: "Booking status updated" });
  } catch (error) {
    console.error("Error updating booking status:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// Admin assign provider to booking
app.put(
  "/api/admin/bookings/:bookingId/assign-provider",
  verifyAdmin,
  async (req, res) => {
    const bookingsCollection = client
      .db("SubidhaHomeService")
      .collection("bookings");
    const providersCollection = client
      .db("SubidhaHomeService")
      .collection("providers");

    try {
      const { bookingId } = req.params;
      const { providerId } = req.body;

      // Get booking details
      const booking = await bookingsCollection.findOne({ bookingId });
      if (!booking) {
        return res.status(404).json({ error: "Booking not found" });
      }

      // Get provider details
      const provider = await providersCollection.findOne({
        _id: new ObjectId(providerId),
      });
      if (!provider) {
        return res.status(404).json({ error: "Provider not found" });
      }

      // Check if provider is approved
      if (provider.status !== "approved") {
        return res.status(400).json({ error: "Provider is not approved" });
      }

      // Check if provider offers the required service category
      if (!provider.serviceCategories?.includes(booking.serviceCategory)) {
        return res
          .status(400)
          .json({ error: "Provider does not offer this service category" });
      }

      // Update booking with provider assignment
      const updateData = {
        providerId: providerId,
        providerInfo: {
          _id: provider._id,
          fullName: provider.fullName,
          businessName: provider.businessName,
          phone: provider.phone,
          email: provider.email,
          serviceAreas: provider.serviceAreas,
          rating: provider.rating || 0,
          completedJobs: provider.completedJobs || 0,
        },
        status: "assigned",
        assignedAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      };

      const result = await bookingsCollection.updateOne(
        { bookingId },
        { $set: updateData }
      );

      if (result.matchedCount === 0) {
        return res.status(404).json({ error: "Booking not found" });
      }

      console.log(
        `✅ Provider ${provider.fullName} assigned to booking ${bookingId}`
      );
      res.json({
        success: true,
        message: "Provider assigned successfully",
        provider: updateData.providerInfo,
      });
    } catch (error) {
      console.error("Error assigning provider:", error);
      res.status(500).json({ error: "Internal Server Error" });
    }
  }
);

// Get user's bookings
app.get("/api/bookings/user/:userId", async (req, res) => {
  const bookingsCollection = client
    .db("SubidhaHomeService")
    .collection("bookings");

  try {
    const { userId } = req.params;

    const bookings = await bookingsCollection
      .find({ customerId: userId })
      .sort({ createdAt: -1 })
      .toArray();

    res.json({ bookings });
  } catch (error) {
    console.error("Error fetching user bookings:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// New endpoint to get providers by category ID
app.get("/providers/by-category/:categoryId", async (req, res) => {
  const providersCollection = client
    .db("SubidhaHomeService")
    .collection("providers");

  try {
    const { categoryId } = req.params;
    const { location } = req.query;

    console.log("🎯 Providers by category endpoint called");
    console.log("📋 CategoryId:", categoryId);
    console.log("📍 Location:", location);

    // Build query using category ID
    let query = {
      status: "approved",
      serviceCategories: { $in: [categoryId] },
    };

    console.log("🔍 Initial query:", JSON.stringify(query, null, 2));

    // Add location filter if provided
    if (location) {
      console.log("🎯 Location matching for:", location);

      // Normalize location for matching
      const normalizedLocation = location.toLowerCase().trim();
      console.log("🎯 Normalized location:", normalizedLocation);

      // Create location patterns for flexible matching
      const locationPatterns = [
        new RegExp(`^${normalizedLocation}$`, "i"),
        new RegExp(`^${normalizedLocation}\\b`, "i"),
        new RegExp(`\\b${normalizedLocation}\\b`, "i"),
        new RegExp(normalizedLocation, "i"),
      ];

      console.log("📍 Location patterns:", locationPatterns);

      // Add location filter to query
      query.$or = [
        { serviceAreas: { $in: locationPatterns } },
        { serviceAreas: { $regex: normalizedLocation, $options: "i" } },
        {
          serviceAreas: {
            $elemMatch: { $regex: normalizedLocation, $options: "i" },
          },
        },
      ];
    }

    console.log("🔍 Final Query:", JSON.stringify(query, null, 2));

    // Execute query
    const providers = await providersCollection.find(query).toArray();

    console.log("📊 Returning real providers:", providers.length, "providers");
    console.log(
      "📊 Provider details:",
      providers.map((p) => ({
        name: p.fullName || p.name,
        serviceCategories: p.serviceCategories,
        serviceAreas: p.serviceAreas,
      }))
    );

    // If no providers found with location, try without location filter
    if (providers.length === 0 && location) {
      console.log("⚠️ No providers found for this category and location");
      console.log(
        "🔄 Trying fallback: providers for category without location filter"
      );

      const fallbackQuery = {
        status: "approved",
        serviceCategories: { $in: [categoryId] },
      };

      const fallbackProviders = await providersCollection
        .find(fallbackQuery)
        .toArray();
      console.log("🔄 Fallback providers found:", fallbackProviders.length);

      if (fallbackProviders.length > 0) {
        return res.json({
          providers: fallbackProviders,
          fallback: true,
          message: `No providers found in ${location}, but found ${fallbackProviders.length} providers for this category in other areas`,
        });
      }
    }

    res.json({ providers });
  } catch (error) {
    console.error("Error fetching providers by category:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// Test endpoint to debug provider search
app.get("/test-provider-search/:serviceId", async (req, res) => {
  const providersCollection = client
    .db("SubidhaHomeService")
    .collection("providers");
  const servicesCollection = client
    .db("SubidhaHomeService")
    .collection("services");

  try {
    const { serviceId } = req.params;
    console.log("🧪 Test endpoint called with serviceId:", serviceId);

    // Get service
    const service = await servicesCollection.findOne({
      _id: new ObjectId(serviceId),
    });
    console.log("🧪 Service found:", service);

    if (!service) {
      return res.json({ error: "Service not found" });
    }

    // Test different queries
    const queries = [
      {
        name: "Old query (services field)",
        query: { status: "approved", services: { $in: [serviceId] } },
      },
      {
        name: "New query (serviceCategories field)",
        query: {
          status: "approved",
          serviceCategories: { $in: [service.category] },
        },
      },
      {
        name: "All approved providers",
        query: { status: "approved" },
      },
    ];

    const results = [];
    for (const { name, query } of queries) {
      const providers = await providersCollection.find(query).toArray();
      results.push({
        name,
        query,
        count: providers.length,
        providers: providers.map((p) => ({
          name: p.fullName || p.name,
          serviceCategories: p.serviceCategories,
          services: p.services,
          serviceAreas: p.serviceAreas,
        })),
      });
    }

    res.json({
      serviceId,
      service: {
        name: service.serviceName,
        category: service.category,
      },
      results,
    });
  } catch (error) {
    console.error("Test endpoint error:", error);
    res.status(500).json({ error: error.message });
  }
});

// ==================== ADMIN PROVIDER ASSIGNMENT ====================

// Get available providers for assignment
app.get("/api/admin/providers/available", verifyAdmin, async (req, res) => {
  try {
    const providersCollection = client
      .db("SubidhaHomeService")
      .collection("providers");

    const providers = await providersCollection
      .find({ status: "active" })
      .project({
        _id: 1,
        fullName: 1,
        email: 1,
        phone: 1,
        specialization: 1,
        experience: 1,
        rating: 1,
        totalJobs: 1,
      })
      .toArray();

    res.json({
      success: true,
      data: { providers },
    });
  } catch (error) {
    console.error("Error fetching available providers:", error);
    res.status(500).json({
      success: false,
      message: "Failed to fetch providers",
      error: error.message,
    });
  }
});

// Assign provider to booking
app.post(
  "/api/admin/bookings/:bookingId/assign-provider",
  verifyAdmin,
  async (req, res) => {
    try {
      const { bookingId } = req.params;
      const { providerId } = req.body;

      if (!providerId) {
        return res.status(400).json({
          success: false,
          message: "Provider ID is required",
        });
      }

      const bookingCollection = client
        .db("SubidhaHomeService")
        .collection("bookings");

      const providersCollection = client
        .db("SubidhaHomeService")
        .collection("providers");

      // Check if booking exists
      const booking = await bookingCollection.findOne({ bookingId });
      if (!booking) {
        return res.status(404).json({
          success: false,
          message: "Booking not found",
        });
      }

      // Check if provider exists
      const provider = await providersCollection.findOne({
        _id: new ObjectId(providerId),
      });
      if (!provider) {
        return res.status(404).json({
          success: false,
          message: "Provider not found",
        });
      }

      // Update booking with provider assignment
      const updateResult = await bookingCollection.updateOne(
        { bookingId },
        {
          $set: {
            assignedProvider: {
              providerId: provider._id,
              providerName: provider.fullName,
              providerEmail: provider.email,
              providerPhone: provider.phone,
            },
            status: "confirmed",
            assignedAt: new Date(),
            updatedAt: new Date(),
          },
        }
      );

      if (updateResult.modifiedCount > 0) {
        // Update provider's job count
        await providersCollection.updateOne(
          { _id: new ObjectId(providerId) },
          {
            $inc: { totalJobs: 1 },
            $set: { updatedAt: new Date() },
          }
        );

        res.json({
          success: true,
          message: "Provider assigned successfully",
          data: {
            bookingId,
            provider: {
              id: provider._id,
              name: provider.fullName,
              email: provider.email,
              phone: provider.phone,
            },
          },
        });
      } else {
        res.status(400).json({
          success: false,
          message: "Failed to assign provider",
        });
      }
    } catch (error) {
      console.error("Error assigning provider:", error);
      res.status(500).json({
        success: false,
        message: "Internal server error",
        error: error.message,
      });
    }
  }
);

server.listen(port, () => {
  console.log(`Home Services Server app Listening on Port: ${port}`);
});
