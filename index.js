const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const SSLCommerzPayment = require("sslcommerz-lts");
const jwt = require("jsonwebtoken");
const express = require("express");
const http = require("http");
const socketIo = require("socket.io");
const cors = require("cors");
require("dotenv").config();
const nodemailer = require("nodemailer");

const app = express();

const server = http.createServer(app);

console.log(server);;

const io = socketIo(server, {
  cors: {
    origin: "http://localhost:5173",
    methods: ["GET", "POST"],
  },
});

// middleware
app.use(express.json());
app.use(cors());

function verifyJWT(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).send("unauthorized access");
  }
  const token = authHeader.split(" ")[1];
  jwt.verify(token, process.env.ACCESS_TOKEN, function (err, decoded) {
    if (err) {
      return res.status(403).send({ message: "forbidden access" });
    }
    req.decoded = decoded;
    next();
  });
}

const port = process.env.PORT || 5000;

const store_id = process.env.STORE_ID;
const store_passwd = process.env.STORE_PASSWORD;
const is_live = false; //true for live, false for sandbox

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASSWORD}@cluster0.5f5xb9l.mongodb.net/?retryWrites=true&w=majority`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  const allServicesCollection = client
    .db("SubidhaHomeService")
    .collection("services");
  const usersCollection = client.db("SubidhaHomeService").collection("users");
  const messageCollection = client.db("SubidhaHomeService").collection("chats");
  const providersCollection = client
    .db("SubidhaHomeService")
    .collection("providers");
  const bookingCollection = client
    .db("SubidhaHomeService")
    .collection("booking");
  const reviewsCollection = client
    .db("SubidhaHomeService")
    .collection("reviews");

  const paymentCollection = client
    .db("SubidhaHomeService")
    .collection("payments");

  const staffCollection = client
    .db("SubidhaHomeService")
    .collection("staffs");

  const timeSlotCollection = client
    .db("SubidhaHomeService")
    .collection("timeSlots");

  const dailyTimeSlots = client
    .db("SubidhaHomeService")
    .collection("dailyTimeSlots");

  const rolesCollection = client
    .db("SubidhaHomeService")
    .collection("roles");

  try {
    // Function to fetch service categories from database and format response
    const fetchServiceCategories = async (query = {}) => {
      try {
        const serviceCategories = await allServicesCollection
          .find(query)
          .sort({ _id: 1 })
          .toArray();

        return serviceCategories.map((serviceCategory) => ({
          _id: serviceCategory._id,
          serviceName: serviceCategory.serviceName,
          icon: serviceCategory.icon,
          isFeatured: serviceCategory.isFeatured,
          totalService: serviceCategory.subCategories.length,
        }));
      } catch (error) {
        console.error("Error fetching service categories:", error);
        throw new Error("Internal Server Error");
      }
    };

    // Endpoint to fetch all featured service categories
    app.get("/allServiceCategories", async (req, res) => {
      try {
        const query = { isFeatured: "yes" };
        const allServiceCategories = await fetchServiceCategories(query);
        res.send(allServiceCategories);
      } catch (error) {
        console.error(error);
        res.status(500).send("Internal Server Error");
      }
    });

    // Endpoint to fetch all service categories
    app.get("/serviceCategories", async (req, res) => {
      try {
        const allServiceCategories = await fetchServiceCategories();
        res.send(allServiceCategories);
      } catch (error) {
        console.error(error);
        res.status(500).send("Internal Server Error");
      }
    });

    // Endpoint to fetch all services
    app.get("/all-services", async (req, res) => {
      try {
        const query = {}; // Define an empty query object to fetch all documents
        const allServices = await allServicesCollection.find(query).toArray(); // Fetch all services from the collection
        res.send(allServices); // Send the fetched services as a response
      } catch (error) {
        res.status(500).send("Internal Server Error"); // Handle any errors that occur during the fetch operation
      }
    });

    // Endpoint to fetch a specific service category by ID
    app.get("/allServiceCategories/:id", async (req, res) => {
      try {
        const serviceId = req.params.id; // Extract the service ID from the request parameters
        const query = {
          _id: new ObjectId(serviceId), // Construct a query to find the service by its ObjectId
        };
        const service = await allServicesCollection.findOne(query); // Find the service in the collection
        res.send(service); // Send the fetched service category as a response
      } catch (error) {
        res.status(500).send("Internal Server Error"); // Handle any errors that occur during the fetch operation
      }
    });

    // Endpoint to update a category by ID
    app.put("/edit-categories/:id", async (req, res) => {
      const categoryId = req.params.id; // Extract the category ID from the request parameters
      console.log(categoryId); // Log the categoryId to console
      const data = req.body; // Extract the data to update from the request body
      console.log(data); // Log the data to console
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
        const result = await allServicesCollection.findOneAndUpdate(query, updateDoc, options); // Perform the update operation
        res.send(result); // Send the result of the update operation as the response
      } catch (error) {
        console.error(error); // Log any errors to console
        res.status(500).send("Internal Server Error"); // Handle any errors with a 500 Internal Server Error response
      }
    });

    // Endpoint to fetch a subcategory within a service category
    app.get("/subcategory/:categoryId/:subCategoryId", async (req, res) => {
      try {
        const categoryId = req.params.categoryId; // Extract the category ID from request parameters
        const subCategoryId = req.params.subCategoryId; // Extract the subcategory ID from request parameters

        const query = {
          _id: new ObjectId(categoryId), // Construct a query to find the category by its ObjectId
        };
        const serviceCategory = await allServicesCollection.findOne(query); // Find the category in the collection

        if (!serviceCategory) { // If category is not found, return 404 with message
          return res.status(404).send("Service category not found");
        }

        const subCategory = serviceCategory.subCategories.find( // Find the subcategory within the found category
          (subCategory) => subCategory.id === subCategoryId
        );

        if (!subCategory) { // If subcategory is not found within the category, return 404 with message
          return res.status(404).send("Subcategory not found");
        }

        // Prepare and send the response with structured data
        res.send({
          serviceCategory: serviceCategory.serviceName,
          subCategory,
          serviceOverview: serviceCategory.serviceOverview,
          faq: serviceCategory.faq,
        });
      } catch (error) {
        console.error(error); // Log any errors to console
        res.status(500).send("Internal Server Error"); // Handle any errors with a 500 Internal Server Error response
      }
    });

    // Endpoint to fetch a service category by serviceName query parameter
    app.get("/service-categories", async (req, res) => {
      let serviceName = req.query.serviceName; // Extract the 'serviceName' query parameter from the request

      // Encoding the serviceName parameter
      serviceName = serviceName.replace(/&/g, "%26"); // Replace '&' with its URL-encoded equivalent '%26'

      if (serviceName) { // Check if 'serviceName' parameter is provided in the request
        const category = await allServicesCollection.findOne({ // Find a category that matches the serviceName using regex
          serviceName: {
            $regex: serviceName, // Use regex to match serviceName
          },
        });
        return res.send(category); // Send the found category as the response
      }
      return res.send({}); // If 'serviceName' parameter is not provided, send an empty object as response
    });

    // Endpoint to fetch users with optional search and pagination
    app.get("/users", async (req, res) => {
      try {
        const searchTerm = req.query.searchText; // Extract the 'searchText' query parameter from the request
        const page = req.query.page; // Extract the 'page' query parameter from the request
        const size = req.query.size; // Extract the 'size' query parameter from the request

        if (searchTerm) { // Check if 'searchText' parameter is provided in the request
          let users = await usersCollection.find().toArray(); // Fetch all users from the collection
          users = users?.filter((user) => { // Filter users based on search criteria
            return (
              user.userName?.toLowerCase().search(searchTerm.toLowerCase()) > -1 || // Check if userName contains searchTerm
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
        const result = await usersCollection.findOneAndUpdate(
          query,
          {
            $set: user, // Update user object if found or insert if not found
          },
          { upsert: true, new: true } // Upsert option to insert new document if not found
        );
        if (result === null || result) { // Check if result is either null or exists
          res.send({ acknowledged: true }); // Send acknowledgment of operation success
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

        const result = await usersCollection.updateOne(filter, updateDoc, options); // Perform update operation
        res.send(result); // Send result of update operation as response
      } catch (error) {
        console.error(error); // Log any errors to console
        res.status(500).json({ message: "Internal server error" }); // Handle errors with 500 Internal Server Error response
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

        const result = await usersCollection.updateOne(filter, updateDoc, options); // Perform update operation
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

    // PATCH endpoint to update user role by UID, with JWT verification middleware
    app.patch("/users/admin/:uid", verifyJWT, async (req, res) => {
      const decodedUID = req.decoded.uid; // Extract decoded UID from JWT payload
      const uid = req.params.uid; // Extract UID from URL parameters
      if (req.query.userId !== decodedUID) { // Verify if userId in query parameter matches decoded UID
        return res.status(403).send({ message: "forbidden access" }); // Return forbidden access if mismatch
      }
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
        const isAdmin = role === "admin" || role === "sub admin" || role === "super admin";

        res.send({ isAdmin }); // Send whether user is admin as JSON response
      } catch (error) {
        console.error("Error fetching user:", error); // Log any errors to console
        res.status(500).send({ error: "Internal Server Error" }); // Handle errors with 500 Internal Server Error response
      }
    });

    // GET endpoint to fetch all providers
    app.get("/all-providers", async (req, res) => {
      try {
        const query = {}; // Define an empty query to fetch all providers
        const result = await providersCollection.find(query).toArray(); // Fetch all providers from collection
        res.send(result); // Send the array of providers as JSON response
      } catch (error) {
        res.status(500).json({ error: "Internal server error" }); // Handle errors with 500 Internal Server Error response
      }
    });

    // POST endpoint to create a new provider
    app.post("/providers", async (req, res) => {
      try {
        const provider = req.body; // Extract provider data from request body
        const result = await providersCollection.insertOne(provider); // Insert new provider document into collection
        res.send(result); // Send the result of the insertion operation as JSON response
      } catch (error) {
        console.error("Error creating provider:", error); // Log any errors to console
        res.status(500).json({ error: "Internal server error" }); // Handle errors with 500 Internal Server Error response
      }
    });

    // GET endpoint to fetch providers based on query parameters
    app.get("/providers", async (req, res) => {
      const { division, district, upazila, serviceCategory } = req.query; // Extract query parameters

      try {
        const query = {
          role: "provider", // Filter providers by role "provider"
        };
        if (division) query.division = division; // Add division filter if provided
        if (district) query.district = district; // Add district filter if provided
        if (upazila) query.upazila = upazila; // Add upazila filter if provided
        if (serviceCategory) query.serviceCategory = serviceCategory; // Add serviceCategory filter if provided

        const serviceProviders = await providersCollection.find(query).toArray(); // Find providers matching the query
        res.json(serviceProviders); // Send providers as JSON response
      } catch (error) {
        res.status(500).json({ error: "Internal Server Error" }); // Handle errors with 500 Internal Server Error response
      }
    });

    // GET endpoint to fetch provider details by UID
    app.get("/providers/:uid", async (req, res) => {
      const uid = req.params.uid; // Extract UID from URL parameters

      try {
        const providerDetails = await providersCollection.findOne({ uid }); // Find provider details by UID
        if (!providerDetails) { // Handle case where provider details are not found
          return res.status(404).json({ message: "Provider not found" });
        }
        res.send(providerDetails); // Send provider details as JSON response
      } catch (error) {
        res.status(500).json({ error: "Internal Server Error" }); // Handle errors with 500 Internal Server Error response
      }
    });

    // Update provider by ID
    app.put("/all-providers/:id", async (req, res) => {
      try {
        const { id } = req.params; // Extract ID from URL parameters
        const { _id, ...updatedProvider } = req.body; // Exclude _id from the update object

        const result = await providersCollection.findOneAndUpdate(
          { _id: new ObjectId(id) }, // Find provider by ObjectId
          { $set: updatedProvider }, // Set updated fields
          { returnOriginal: false } // Option to return the updated document
        );

        res.send(result); // Send the updated provider document as response
      } catch (err) {
        res.status(500).json({ message: err.message }); // Handle errors with 500 Internal Server Error response
      }
    });

    // Delete provider by ID
    app.delete("/all-providers/:id", async (req, res) => {
      try {
        const { id } = req.params; // Extract ID from URL parameters
        const result = await providersCollection.deleteOne({ _id: new ObjectId(id) }); // Delete provider by ObjectId

        if (result.deletedCount === 0) { // Handle case where provider was not found
          return res.status(404).json({ message: "Provider not found" });
        }

        res.json({ message: "Provider deleted successfully" }); // Send success message as JSON response
      } catch (err) {
        res.status(500).json({ message: err.message }); // Handle errors with 500 Internal Server Error response
      }
    });

    // GET endpoint to check if a user with given UID is a provider
    app.get("/users/provider/:uid", async (req, res) => {
      const uid = req.params.uid; // Extract UID from URL parameters
      const query = { uid: uid }; // Define query to find user by UID

      try {
        const user = await providersCollection.findOne(query); // Find user in providers collection

        // Check if user exists and if their role is "provider"
        const isProvider = user?.role === "provider";

        console.log({ isProvider }); // Log whether user is a provider
        res.send({ isProvider }); // Send whether user is a provider as JSON response
      } catch (error) {
        console.error("Error fetching provider:", error); // Log any errors to console
        res.status(500).json({ error: "Internal Server Error" }); // Handle errors with 500 Internal Server Error response
      }
    });

    // API endpoint to get booking details by booking ID
    app.get("/booking/:id", async (req, res) => {
      const bookingID = req.params.id;
      try {
        // Create a query object to find the booking by its ID
        const query = {
          _id: new ObjectId(bookingID),
        };
        // Find the booking details using the query
        const bookingDetails = await bookingCollection.findOne(query);
        // Send the booking details back to the client
        res.send(bookingDetails);
      } catch (error) {
        // If there's an error, respond with a 500 status and an error message
        res.status(500).json({ error: "Internal Server Error" });
      }
    });

    // API endpoint to handle booking creation
    app.post("/booking", async (req, res) => {
      const newBooking = req.body;
      try {
        // Insert the new booking into the booking collection
        const result = await bookingCollection.insertOne(newBooking);
        // Send the result of the insert operation back to the client
        res.send(result);
      } catch (error) {
        // If there's an error, respond with a 500 status and an error message
        res.status(500).json({ error: "Internal Server Error" });
      }
    });

    // Function to handle fetching bookings based on a query
    async function fetchBookings(query, res) {
      try {
        const bookingList = await bookingCollection.find(query).toArray();
        res.send(bookingList);
      } catch (error) {
        res.status(500).json({ error: "Internal Server Error" });
      }
    }

    // API endpoint to get bookings for a specific user
    app.get("/user-bookings/:uid", async (req, res) => {
      const userID = req.params.uid;
      const query = { userID };
      await fetchBookings(query, res);
    });

    // API endpoint to get bookings for a specific provider
    app.get("/provider-bookings/:providerId", async (req, res) => {
      const providerID = req.params.providerId;
      const query = { providerID };
      await fetchBookings(query, res);
    });

    // Endpoint to fetch recent bookings for a specific provider within the current month
    app.get("/provider-recent-bookings/:providerId", async (req, res) => {
      // Extract provider ID from request parameters
      const providerID = req.params.providerId;

      // Construct MongoDB query to fetch bookings updated within the current month
      const query = {
        providerID, // Filter by provider ID
        updated: {
          $gte: new Date(new Date().getFullYear(), new Date().getMonth(), 1), // Start of current month
          $lt: new Date(new Date().getFullYear(), new Date().getMonth() + 1, 1) // Start of next month
        }
      };

      // Call function to fetch bookings based on the constructed query
      await fetchBookings(query, res);
    });

    // Endpoint to fetch provider bookings and reviews count based on providerID
    app.get("/provider-bookings-reviews/:providerId", async (req, res) => {
      try {
        // Extract providerID from request parameters
        const providerID = req.params.providerId;

        // Fetch bookings from bookingCollection for the given providerID
        const bookings = await bookingCollection
          .find({
            providerID,
          })
          .toArray();

        const provider = await providersCollection.findOne({ uid: providerID });

        // Fetch reviews from reviewsCollection for the given providerID
        const reviews = await reviewsCollection
          .find({
            providerID,
          })
          .toArray();

        // Send response with total number of bookings and reviews for the provider
        res.send({
          totalBookings: bookings.length,
          totalReviews: reviews.length,
          totalServices: provider.myServices?.length ? provider.myServices.length : 0,
        });
      } catch (error) {
        // Handle any errors that occur during fetching or sending response
        console.error("Error fetching provider bookings and reviews:", error);
        res.status(500).json({ error: "Internal server error" });
      }
    });

    // Endpoint to fetch provider details based on providerID
    app.get("/providers/:uid", async (req, res) => {
      try {
        // Extract providerID from request parameters
        const providerID = req.params.uid;

        // Query to find provider by uid
        const query = {
          uid: providerID,
        };

        // Find provider details in providersCollection
        const provider = await providersCollection.findOne(query);

        // If provider is found, send provider details in response
        if (provider) {
          res.send(provider);
        } else {
          // If provider is not found, send 404 Not Found response
          res.status(404).json({ error: "Provider not found" });
        }
      } catch (error) {
        // Handle any errors that occur during fetching or sending response
        console.error("Error fetching provider details:", error);
        res.status(500).json({ error: "Internal server error" });
      }
    });

    // API endpoint to update the status of a booking by booking ID
    app.patch("/booking-status/:bookingId", async (req, res) => {
      const { status } = req.body; // Extract the new status from the request body
      const bookingId = req.params.bookingId; // Extract the booking ID from the URL parameters

      try {
        // Create a filter to find the booking by its ID
        const filter = {
          _id: new ObjectId(bookingId),
        };

        // Create an update document to set the new booking status
        const updateDoc = {
          $set: {
            bookingStatus: status,
          },
        };

        // Update the booking document with the new status
        const result = await bookingCollection.updateOne(filter, updateDoc);

        // Send the result of the update operation back to the client
        res.send(result);
      } catch (error) {
        // If there's an error, respond with a 500 status and an error message
        res.status(500).json({ error: "Internal Server Error" });
      }
    });

    // API endpoint to retrieve all bookings
    app.get("/all-bookings", async (req, res) => {
      try {
        // Create an empty query object to fetch all documents from the collection
        const query = {};
        // Fetch all bookings from the booking collection
        const allBookings = await bookingCollection.find(query).toArray();
        // Send the list of all bookings back to the client
        res.send(allBookings);
      } catch (error) {
        // If there's an error, respond with a 500 status and an error message
        res.status(500).json({ error: "Internal Server Error" });
      }
    });

    // POST endpoint to add a review and update booking status
    app.post("/review", async (req, res) => {
      const review = req.body; // Extract review data from request body
      console.log(review); // Log the review data for debugging

      try {
        const query = { _id: new ObjectId(review.bookingId) }; // Define query to find booking by ID
        const options = { upsert: true }; // Options to upsert if booking ID doesn't exist

        // Update booking status to indicate review has been written
        const updateDoc = {
          $set: { hasWrittenReview: true }
        };
        await bookingCollection.updateOne(query, updateDoc, options); // Update booking collection

        const result = await reviewsCollection.insertOne(review); // Insert review into reviews collection
        res.send(result); // Send the result of review insertion as response
      } catch (error) {
        console.error("Error adding review:", error); // Log any errors to console
        res.status(500).json({ error: "Internal Server Error" }); // Handle errors with 500 Internal Server Error response
      }
    });

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

    // GET endpoint to find services matching searchText
    app.get("/find-services", async (req, res) => {
      const searchText = req.query.searchText; // Extract searchText from query parameters

      if (searchText) {
        try {
          const allServiceCategories = await allServicesCollection.find({}).toArray(); // Fetch all service categories

          const matchedServices = [];

          // Iterate through each service category
          allServiceCategories.forEach((serviceCategory) => {
            const services = serviceCategory.subCategories; // Get sub-categories of each service category

            // Iterate through each service in sub-categories
            services.forEach((service) => {
              // Check if service name contains searchText (case-insensitive)
              if (service.serviceName.toLowerCase().includes(searchText.toLowerCase())) {
                matchedServices.push({
                  categoryId: serviceCategory._id,
                  subCategoryId: service.id,
                  serviceName: service.serviceName,
                });
              }
            });
          });

          res.send(matchedServices); // Send matched services as JSON response
        } catch (error) {
          console.error("Error finding services:", error); // Log any errors to console
          res.status(500).json({ error: "Internal Server Error" }); // Handle errors with 500 Internal Server Error response
        }
      } else {
        res.send([]); // Send empty array if searchText is not provided
      }
    });

    // Endpoint to fetch user bookings and reviews count based on userID
    app.get("/user-bookings-reviews/:uid", async (req, res) => {
      // Extract userID from request parameters
      const userID = req.params.uid;

      // Fetch bookings from bookingCollection for the given userID
      const bookings = await bookingCollection
        .find({
          userID,
        })
        .toArray();

      // Fetch reviews from reviewsCollection for the given userID
      const reviews = await reviewsCollection
        .find({
          userID,
        })
        .toArray();

      // Send response with total number of bookings and reviews for the user
      res.send({
        totalBookings: bookings.length,
        totalReviews: reviews.length,
      });
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

    // POST endpoint to edit or update provider service details
    app.post("/edit-provider-service/:providerId", async (req, res) => {
      const providerId = req.params.providerId; // Extract providerId from URL parameters
      const { editService } = req.body; // Extract editService object from request body

      try {
        const provider = await providersCollection.findOne({ uid: providerId }); // Find provider by uid

        if (provider) {
          if (provider.myServices && provider.myServices.length > 0) {
            // Update existing service if found
            const matchedService = provider.myServices.find((service) => service.serviceName === editService.serviceName);

            if (matchedService) {
              // Update existing matched service
              matchedService.amount = editService.amount;
              matchedService.details = editService.details;
              matchedService.title = editService.title;

              // Check if selectedFileURL has changed
              if (matchedService.selectedFileURL !== editService.selectedFileURL) {
                matchedService.selectedFileURL = editService.selectedFileURL;
              }

              // Filter out updated service from rest of services
              const restServices = provider.myServices.filter((service) => service.serviceName !== editService.serviceName);

              // Update provider document with updated services array
              const result = await providersCollection.findOneAndUpdate(
                { uid: providerId },
                { $set: { myServices: [...restServices, matchedService] } },
                { returnOriginal: false }
              );

              return res.send(result); // Send updated result as response
            } else {
              // Update services array by adding new service
              const restServices = provider.myServices.filter((service) => service.serviceName !== editService.serviceName);
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
          const matchedService = provider.myServices.find((service) => service.serviceName === serviceName);

          return res.send(matchedService); // Send matchedService if found
        }

        res.send({}); // Send empty object if provider or myServices array not found
      } catch (error) {
        console.error("Error fetching provider service:", error); // Log any errors to console
        res.status(500).json({ error: "Internal Server Error" }); // Handle errors with 500 Internal Server Error response
      }
    });


    function generateTransactionId() {
      const tran_id = new ObjectId().toString();
      return tran_id;
    }

    // POST endpoint to initiate a payment
    app.post("/make-payment", async (req, res) => {
      const bookingInfo = req.body; // Extract bookingInfo from request body

      // Find booking details in bookingCollection based on bookingInfo._id
      const booking = await bookingCollection.findOne({
        _id: new ObjectId(bookingInfo._id),
      });

      // Define payment data for SSLCommerzPayment integration
      const data = {
        total_amount: booking.totalAmount,
        currency: "BDT",
        tran_id: generateTransactionId(), // Generate unique transaction ID using generateTransactionId() function
        success_url: `https://subidha-home-services-server3792.glitch.me/payment/success/${booking._id}`, // Success URL for redirection after successful payment
        fail_url: "http://localhost:3030/fail", // Failure URL
        cancel_url: "http://localhost:3030/cancel", // Cancel URL
        ipn_url: "http://localhost:3030/ipn", // IPN (Instant Payment Notification) URL
        shipping_method: "Courier",
        product_name: "Cleaning Service",
        product_category: "Clean",
        product_profile: "general",
        cus_name: "Customer Name",
        cus_email: "customer@example.com",
        cus_add1: "Dhaka",
        cus_add2: "Dhaka",
        cus_city: "Dhaka",
        cus_state: "Dhaka",
        cus_postcode: "1000",
        cus_country: "Bangladesh",
        cus_phone: "01943104565",
        cus_fax: "01711111111",
        ship_name: "Customer Name",
        ship_add1: "Dhaka",
        ship_add2: "Dhaka",
        ship_city: "Dhaka",
        ship_state: "Dhaka",
        ship_postcode: 1000,
        ship_country: "Bangladesh",
      };

      console.log(data); // Log payment data for debugging purposes

      const sslcz = new SSLCommerzPayment(store_id, store_passwd, is_live); // Initialize SSLCommerzPayment instance
      sslcz.init(data).then((apiResponse) => {
        // Redirect the user to payment gateway using GatewayPageURL from apiResponse
        let GatewayPageURL = apiResponse.GatewayPageURL;
        res.send({ url: GatewayPageURL }); // Send payment gateway URL as response

        // console.log("Redirecting to: ", GatewayPageURL); // Optional: Log redirection URL
      });

      // Function to format date in a specific format
      function formatDate(date) {
        const options = { year: 'numeric', month: 'long', day: 'numeric' };
        return date.toLocaleDateString('en-US', options);
      }

      const payment = {
        bookingId: bookingInfo._id,
        bookingDetails: booking,
        paidStatus: false,
        transationId: data.tran_id, // Store transaction ID in payment document
        userID: bookingInfo.userID,
        providerID: bookingInfo.providerID,
      };

      const options = { upsert: true }; // Options for findOneAndUpdate operation

      // Update or insert payment information in paymentCollection
      const result = await paymentCollection.findOneAndUpdate(
        { bookingId: bookingInfo._id },
        { $set: payment }, // Set payment data
        options // Pass options for upsert behavior
      );

      // POST endpoint to handle successful payment callback
      app.post("/payment/success/:bookingId", async (req, res) => {
        // Function to generate a unique invoice number using ObjectId
        function generateInvoiceNumber() {
          const invoiceNumber = new ObjectId().toString();
          return invoiceNumber;
        }

        let invoiceNumber = generateInvoiceNumber(); // Generate invoice number

        // Update payment status and invoice details in paymentCollection
        const paymentUpdateResult = await paymentCollection.updateOne(
          { bookingId: req.params.bookingId }, // Find payment by bookingId
          {
            $set: {
              paidStatus: true, // Update paidStatus to true
              paymentDate: formatDate(new Date()), // Format payment date
              invoiceNumber, // Assign generated invoice number
            },
          }
        );

        // Function to get formatted date in YYYY/MM/DD format
        function getFormattedDate() {
          const date = new Date();
          const year = date.getFullYear();
          const month = date.getMonth() + 1; // Months are zero-based, so add 1
          const day = date.getDate();
          return `${year}/${month}/${day}`;
        }

        // Update booking details with payment status and invoice information in bookingCollection
        const bookingUpdateResult = await bookingCollection.updateOne(
          { _id: new ObjectId(req.params.bookingId) }, // Find booking by _id
          {
            $set: {
              paidStatus: true, // Update paidStatus to true
              invoiceNumber, // Assign generated invoice number
              invoiceDate: getFormattedDate(), // Format invoice date
            },
          }
        );

        // Redirect to success URL with bookingId if both updates were successful
        if (
          paymentUpdateResult.modifiedCount > 0 &&
          bookingUpdateResult.modifiedCount > 0
        ) {
          res.redirect(`https://subidha-home-service-43040.web.app/payment/success/${req.params.bookingId}`);
        }
      });
    });

    // GET endpoint to retrieve payment details based on transaction ID
    app.get("/payment/:transationId", async (req, res) => {
      const transationId = req.params.transationId; // Extract transactionId from URL parameters
      console.log("Transaction Id", transationId); // Log transactionId for debugging purposes

      const query = { transationId }; // Define MongoDB query object to find payment by transactionId

      try {
        const payment = await paymentCollection.findOne(query); // Find payment document in paymentCollection

        console.log(payment); // Log payment details for debugging purposes

        res.send(payment); // Send payment details as JSON response
      } catch (error) {
        console.error("Error fetching payment details:", error); // Log any errors to console
        res.status(500).json({ error: "Internal Server Error" }); // Handle errors with 500 Internal Server Error response
      }
    });

    // POST endpoint to manage provider time slots
    app.post('/time-slots', async (req, res) => {
      const { providerId, slots } = req.body; // Extract providerId and slots from request body

      try {
        let providerSlot = await timeSlotCollection.findOne({ providerId }); // Find time slots for the provider

        if (providerSlot) {
          // Update the existing document with new slots
          providerSlot.slots = { ...providerSlot.slots, ...slots }; // Merge existing slots with new slots

          const options = { upsert: true, returnOriginal: false }; // Options for findOneAndReplace

          const result = await timeSlotCollection.findOneAndReplace(
            { providerId },
            providerSlot,
            options
          );

          console.log(result); // Log updated result for debugging purposes

          res.send(result); // Send updated result as JSON response
        } else {
          // Insert new document for the provider if not found
          const result = await timeSlotCollection.insertOne({ providerId, slots });

          res.send(result); // Send insertion result as JSON response
        }
      } catch (error) {
        console.error("Error managing time slots:", error.message); // Log error message to console
        res.status(500).json({ error: "Internal Server Error" }); // Handle errors with 500 Internal Server Error response
      }
    });

    app.get("/get-available-slots/", async (req, res) => {
      const serviceManId = req.query.serviceManId;
      const selectedDate = req.query.selectedDate;
      const selectedWeekDay = req.query.selectedWeekDay;

      try {
        // Find all bookings for the service man on the selected date and weekday
        const alreadyBooked = await bookingCollection.find({
          providerID: serviceManId,
          selectedDate,
          selectedWeekDay,
        }).toArray();

        // Find the available time slots for the service man
        const availableSlots = await timeSlotCollection.findOne({ providerId: serviceManId });

        if (alreadyBooked.length > 0) {
          if (availableSlots?.slots[selectedWeekDay]) {
            // Get the already booked slots
            const bookingSlots = alreadyBooked.map(booking => booking.selectedSlot);

            // Filter out the booked slots from the available slots
            const remainingSlots = availableSlots?.slots[selectedWeekDay]?.filter(slot => !bookingSlots.includes(slot));

            res.send(remainingSlots);
          } else {
            res.send([]); // No available slots if slots for the selected weekday are not found
          }
        } else {
          // If no bookings exist for the selected date and weekday
          const timeSlots = await dailyTimeSlots.find({}).toArray();
          const remainingSlots = availableSlots?.slots[selectedWeekDay]?.filter(slot => !timeSlots.includes(slot));

          if (remainingSlots) {
            res.send(remainingSlots);
          } else {
            res.send([]);
          }
        }
      } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Internal server error" });
      }
    });


    app.post('/roles', async (req, res) => {
      const { roleName, permissions } = req.body;

      // Validate request body
      if (!roleName || !Array.isArray(permissions)) {
        return res.status(400).send({ message: 'Invalid data format' });
      }

      const role = {
        roleName,
        permissions,
        createdAt: new Date(),
        updatedAt: new Date()
      };

      try {
        // Update or insert the role in the rolesCollection
        const filter = { roleName: { $regex: new RegExp(`^${roleName}$`, 'i') } }; // Case insensitive match for roleName
        const updateDocument = {
          $set: {
            roleName: role.roleName,
            permissions: role.permissions,
            updatedAt: new Date()
          }
        };
        const options = { upsert: true, returnOriginal: false }; // Upsert if not found, return updated document

        const result = await rolesCollection.findOneAndUpdate(filter, updateDocument, options);

        // Check if the role was updated or inserted
        if (result.lastErrorObject.updatedExisting) {
          res.send({ message: 'Role updated successfully' });
        } else {
          res.send({ message: 'Role inserted successfully' });
        }
      } catch (error) {
        console.error('Failed to create or update role:', error);
        res.status(500).send({ message: 'Failed to create or update role' });
      }
    });

    app.get('/roles', async (req, res) => {
      try {
        const query = {};
        const result = await rolesCollection.find(query).toArray();
        res.send(result);
      } catch (error) {
        res.status(500).json({ error: "Internal server error" });
      }
    })

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
            user: "subidhahomeservice@gmail.com",
            pass: "gqyqxsjdqygqohbw",
          },
        });

        const mail_configs = {
          from: "subidhahomeservice@gmail.com",
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

    app.post("/send-email", (req, res) => {
      console.log(req.body);
      sendEmail(req.body)
        .then((response) => res.send({ message: "Email sent successfully" }))
        .catch((error) => res.status(500).send(error.message));
    });

    app.get("/jwt", async (req, res) => {
      const uid = req.query.uid;
      const query = { uid };
      const user = await usersCollection.findOne(query);
      if (user) {
        const token = jwt.sign({ uid }, process.env.ACCESS_TOKEN, {
          expiresIn: "1h",
        });
        return res.send({ accessToken: token });
      }
      res.status(403).send({ accessToken: "" });
    });

    app.get("/payments/:id", async (req, res) => {
      const userId = req.params.id;
      console.log(userId);
      try {
        const query = {
          $or: [
            { userID: userId, },
            { providerID: userId }
          ],

          paidStatus: true,
        }
        const payments = await bookingCollection.find(query).toArray();
        res.send(payments);
      } catch (error) {
        res.status(500).json({ error: "Internal server error" });
      }
    })

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
          providerId
        }
        const staffs = await staffCollection.find(query).toArray();
        res.send(staffs);
      } catch (error) {
        res.status(500).json({ error: "Internal server error" });
      }
    })

    app.get("/chats/:roomId", async (req, res) => {
      const roomId = req.params.roomId;
      const query = {
        roomId,
      };
      const result = await messageCollection.findOne(query);
      if (result) {
        res.send(result);
      } else {
        res.send({ messages: [] });
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

            return {
              uid: user.uid,
              userName: user.userName,
              photoURL: user.photoURL,
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

    io.on("connection", (socket) => {
      socket.on("joinRoom", (sessionId) => {
        socket.join(sessionId);
      });

      const roomParticipants = {};
      socket.on("joinRoom", async ({ uid1, uid2 }) => {
        // Ensure that the room ID is unique for the conversation
        let roomId;

        const result = await messageCollection.findOne({
          $or: [
            { roomId: [uid1, uid2].sort().join("-") },
            { roomId: [uid2, uid1].sort().join("-") },
          ],
        });

        if (result) {
          roomId = result.roomId;
        } else {
          roomId = [uid1, uid2].sort().join("-");
        }
        // Check if the room already has two participants
        const participants = roomParticipants[roomId] || [];
        if (participants.length < 2) {
          socket.join(roomId);

          // Add the participant to the list
          roomParticipants[roomId] = participants.concat(socket.id);

          // Notify the client about successful room join
          socket.emit("roomJoined", { success: true, roomId });
        } else {
          // Notify the client that the room is full
          socket.emit("roomJoined", {
            success: false,
            message: "Room is full",
          });
        }
      });

      socket.on("typing", ({ roomId, senderId, receiverId }) => {
        io.to(roomId).emit(`typing-${receiverId}`, { senderId });
      });

      socket.on("notTyping", ({ roomId, senderId, receiverId }) => {
        io.to(roomId).emit(`notTyping-${receiverId}`, { senderId });
      });

      socket.on(
        "privateMessage",
        async ({ roomId, senderId, receiverId, message }) => {
          try {
            const conversation = await messageCollection.findOneAndUpdate(
              {
                roomId: roomId,
              },
              {
                $push: {
                  messages: { senderId, message },
                },
                $set: {
                  senderId,
                  receiverId,
                  seenStatus: {
                    [senderId]: true,
                    [receiverId]: false,
                  },
                },
              },
              { upsert: true, new: true }
            );
            io.to(roomId).emit(`privateMessage-${receiverId}`, {
              senderId,
              message,
            });
            io.to(roomId).emit(`myMessage-${senderId}`, { senderId, message });
            return conversation;
          } catch (error) {
            console.error("Error saving message:", error);
            throw error;
          }
        }
      );
    });

    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("Subidha Home Service Server is Running...");
});

server.listen(port, () => {
  console.log(`Home Services Server app Listening on Port: ${port}`);
});


