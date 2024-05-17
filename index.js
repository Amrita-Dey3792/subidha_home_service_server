const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const SSLCommerzPayment = require("sslcommerz-lts");
const jwt = require("jsonwebtoken");
const express = require("express");
const http = require("http");
const socketIo = require("socket.io");
const cors = require("cors");
require("dotenv").config();

const app = express();

const server = http.createServer(app);

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

  try {
    app.get("/allServiceCategories", async (req, res) => {
      try {
        const query = {};
        const serviceCategories = await allServicesCollection
          .find(query)
          .sort({ _id: 1 })
          .toArray();
        const allServiceCategory = serviceCategories.map((serviceCategory) => ({
          _id: serviceCategory._id,
          serviceName: serviceCategory.serviceName,
          icon: serviceCategory.icon,
          totalService: serviceCategory.subCategories.length,
        }));
        res.send(allServiceCategory);
      } catch (error) {
        console.error(error);
        res.status(500).send("Internal Server Error");
      }
    });

    app.get("/allServiceCategories/:id", async (req, res) => {
      try {
        const serviceId = req.params.id;
        const query = {
          _id: new ObjectId(serviceId),
        };
        const service = await allServicesCollection.findOne(query);
        res.send(service);
      } catch (error) {
        res.status(500).send("Internal Server Error");
      }
    });

    app.get("/subcategory/:categoryId/:subCategoryId", async (req, res) => {
      try {
        const categoryId = req.params.categoryId;
        const subCategoryId = req.params.subCategoryId;

        const query = {
          _id: new ObjectId(categoryId),
        };
        const serviceCategory = await allServicesCollection.findOne(query);

        if (!serviceCategory) {
          return res.status(404).send("Service category not found");
        }

        const subCategory = serviceCategory.subCategories.find(
          (subCategory) => subCategory.id === subCategoryId
        );

        if (!subCategory) {
          return res.status(404).send("Subcategory not found");
        }

        res.send({
          serviceCategory: serviceCategory.serviceName,
          subCategory,
          serviceOverview: serviceCategory.serviceOverview,
          faq: serviceCategory.faq,
        });
      } catch (error) {
        console.error(error);
        res.status(500).send("Internal Server Error");
      }
    });

    app.get("/service-categories", async (req, res) => {
      let serviceName = req.query.serviceName;

      // Encoding the serviceName parameter
      serviceName = serviceName.replace(/&/g, "%26");

      if (serviceName) {
        const category = await allServicesCollection.findOne({
          serviceName: {
            $regex: serviceName,
          },
        });
        return res.send(category);
      }
      return res.send({});
    });

    app.get("/users", async (req, res) => {
      try {
        const searchTerm = req.query.searchText;
        const page = req.query.page;
        const size = req.query.size;
        if (searchTerm) {
          let users = await usersCollection.find().toArray();
          users = users?.filter((user) => {
            return (
              user.userName?.toLowerCase().search(searchTerm.toLowerCase()) >
                -1 ||
              user.email?.toLowerCase().search(searchTerm.toLowerCase()) > -1 ||
              user.phone?.toLowerCase().search(searchTerm.toLowerCase()) > -1
            );
          });
          const count = users.count;
          res.send({ users, count });
          return;
        }
        const users = await usersCollection
          .find()
          .skip(page * size)
          .limit(parseInt(size))
          .toArray();
        const count = await usersCollection.estimatedDocumentCount();
        res.json({ users, count });
      } catch (error) {
        console.error(error);
        res.status(500).send("Internal Server Error");
      }
    });

    app.post("/users", async (req, res) => {
      try {
        const user = req.body;
        const query = {
          uid: user.uid,
        };
        const result = await usersCollection.findOneAndUpdate(
          query,
          {
            $set: user,
          },
          { upsert: true, new: true }
        );
        if (result === null || result) {
          res.send({ acknowledged: true });
        }
      } catch (error) {
        console.error("Error creating user:", error);
        res.status(500).json({ error: "Internal server error" });
      }
    });

    app.get("/users/:uid", async (req, res) => {
      try {
        const uid = req.params.uid;
        const query = {
          uid,
        };
        const user = await usersCollection.findOne(query);
        res.send(user);
      } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Internal server error" });
      }
    });

    app.post("/users/:uid", async (req, res) => {
      try {
        const data = req.body;
        const uid = req.params.uid;

        const filter = {
          uid,
        };

        const options = { upsert: true };

        const updateDoc = {
          $set: {
            [Object.keys(data)[0]]: Object.values(data)[0],
          },
        };
        const result = await usersCollection.updateOne(
          filter,
          updateDoc,
          options
        );
        res.send(result);
      } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Internal server error" });
      }
    });

    app.put("/update-status/:uid", async (req, res) => {
      try {
        const uid = req.params.uid;
        const status = req.body.status;
        // Find the user by username and update the status
        const filter = {
          uid,
        };
        const options = { upsert: true };
        const updateDoc = {
          $set: {
            status,
          },
        };
        const result = await usersCollection.updateOne(
          filter,
          updateDoc,
          options
        );
        res.send(result);
      } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Internal server error" });
      }
    });

    app.put("/user/update-image/:uid", async (req, res) => {
      const userId = req.params.uid;
      const { photoURL } = req.body.photoURL;

      try {
        const updateResult = await usersCollection.updateOne(
          { uid: userId },
          { $set: { photoURL } }
        );
        res.json(updateResult);
      } catch (err) {
        console.error("Error updating image:", err);
        res.status(500).json({ message: "Internal server error" });
      }
    });

    app.patch("/users/admin/:uid", verifyJWT, async (req, res) => {
      const decodedUID = req.decoded.uid;
      const uid = req.params.uid;
      if (req.query.userId !== decodedUID) {
        return res.status(403).send({ message: "forbidden access" });
      }
      const { role } = req.body;
      try {
        const filter = {
          uid,
        };
        // const options = { upsert: true };
        const updateDoc = {
          $set: {
            role,
          },
        };
        const result = await usersCollection.updateOne(filter, updateDoc);
        res.send(result);
      } catch (err) {
        res.status(500).json({ message: "Internal server error" });
      }
    });

    app.get("/users/admin/:uid", async (req, res) => {
      const uid = req.params.uid;
      const query = {
        uid: uid,
      };
      const user = await usersCollection.findOne(query);

      res.send({
        isAdmin:
          user?.role === "Admin" ||
          user?.role === "Sub admin" ||
          user?.role === "Super admin",
      });
    });

    app.post("/providers", async (req, res) => {
      try {
        const provider = req.body;
        const result = await providersCollection.insertOne(provider);
        res.send(result);
      } catch (error) {
        console.error("Error creating user:", error);
        res.status(500).json({ error: "Internal server error" });
      }
    });

    app.get("/providers", async (req, res) => {
      const { division, district, upazila, serviceCategory } = req.query;

      try {
        const query = {};
        if (division) query.division = division;
        if (district) query.district = district;
        if (upazila) query.upazila = upazila;
        if (serviceCategory) query.serviceCategory = serviceCategory;

        const serviceProviders = await providersCollection
          .find(query)
          .toArray();
        res.json(serviceProviders);
      } catch (error) {
        res.status(500).json({ error: "Internal Server Error" });
      }
    });

    app.get("/providers/:uid", async (req, res) => {
      const uid = req.params.uid;
      try {
        const providerDetails = await providersCollection.findOne({ uid });
        res.send(providerDetails);
      } catch (error) {
        res.status(500).json({ error: "Internal Server Error" });
      }
    });

    app.get("/users/provider/:uid", async (req, res) => {
      const uid = req.params.uid;
      const query = {
        uid: uid,
      };
      const user = await providersCollection.findOne(query);
      console.log({ isProvider: user?.role === "provider" });
      res.send({ isProvider: user?.role === "provider" });
    });

    app.post("/booking", async (req, res) => {
      const newBooking = req.body;
      try {
        const result = await bookingCollection.insertOne(newBooking);
        res.send(result);
      } catch (error) {
        res.status(500).json({ error: "Internal Server Error" });
      }
    });

    app.get("/booking/:uid", async (req, res) => {
      const userUID = req.params.uid;

      try {
        const query = {
          userUID,
        };
        const bookingList = await bookingCollection.find(query).toArray();
        res.send(bookingList);
      } catch (error) {
        res.status(500).json({ error: "Internal Server Error" });
      }
    });

    app.get("/provider-bookings/:providerId", async (req, res) => {
      const serviceManUID = req.params.providerId;

      try {
        const query = {
          serviceManUID,
        };
        const bookingList = await bookingCollection.find(query).toArray();
        res.send(bookingList);
      } catch (error) {
        res.status(500).json({ error: "Internal Server Error" });
      }
    });

    app.get("/booking-details/:id", async (req, res) => {
      const bookingID = req.params.id;
      try {
        const query = {
          _id: new ObjectId(bookingID),
        };
        const bookingDetails = await bookingCollection.findOne(query);
        res.send(bookingDetails);
      } catch (error) {
        res.status(500).json({ error: "Internal Server Error" });
      }
    });

    app.patch("/booking-status/:bookingId", async (req, res) => {
      const { status } = req.body;

      const bookingId = req.params.bookingId;

      try {
        const filter = {
          _id: new ObjectId(bookingId),
        };

        const updateDoc = {
          $set: {
            bookingStatus: status,
          },
        };

        const result = await bookingCollection.updateOne(filter, updateDoc);

        res.send(result);
      } catch (error) {
        res.status(500).json({ error: "Internal Server Error" });
      }
    });

    app.get("/provider-details/:uid", async (req, res) => {
      const providerID = req.params.uid;
      try {
        const query = {
          uid: providerID,
        };
        const provider = await providersCollection.findOne(query);
        res.send(provider);
      } catch (error) {
        res.status(500).json({ error: "Internal Server Error" });
      }
    });

    app.post("/review", async (req, res) => {
      const review = req.body;
      try {
        const result = await reviewsCollection.insertOne(review);
        res.send(result);
      } catch (error) {
        res.status(500).json({ error: "Internal Server Error" });
      }
    });

    app.get("/reviews/:providerId", async (req, res) => {
      const serviceManUID = req.params.providerId;
      try {
        const query = { serviceManUID };
        const reviews = await reviewsCollection
          .find(query)
          .sort({ _id: -1 })
          .toArray();
        res.send(reviews);
      } catch (error) {
        res.status(500).json({ error: "Internal Server Error" });
      }
    });

    app.get("/find-services", async (req, res) => {
      const searchText = req.query.searchText;
      if (searchText) {
        const allServiceCategories = await allServicesCollection
          .find({})
          .toArray();
        const matchedServices = [];
        allServiceCategories.map((serviceCategory) => {
          const services = serviceCategory.subCategories;
          services.map((service) => {
            if (
              service.serviceName
                .toLowerCase()
                .includes(searchText.toLowerCase())
            ) {
              matchedServices.push({
                categoryId: serviceCategory._id,
                subCategoryId: service.id,
                serviceName: service.serviceName,
              });
            }
          });
        });
        return res.send(matchedServices);
      }
      res.send([]);
    });

    app.get("/user-bookings-reviews/:uid", async (req, res) => {
      const userUID = req.params.uid;

      const bookings = await bookingCollection
        .find({
          userUID,
        })
        .toArray();
      const reviews = await reviewsCollection
        .find({
          userUID,
        })
        .toArray();
      res.send({
        totalBookings: bookings.length,
        totalReviews: reviews.length,
      });
    });

    app.get("/user-reviews/:uid", async (req, res) => {
      const userUID = req.params.uid;
      try {
        const query = {
          userUID,
        };
        const reviews = await reviewsCollection.find(query).toArray();
        res.send(reviews);
      } catch (error) {}
    });

    app.post("/edit-provider-service/:providerId", async (req, res) => {
      const providerId = req.params.providerId;
      const { editService } = req.body;

      try {
        const provider = await providersCollection.findOne({ uid: providerId });

        if (provider) {
          if (provider.myServices && provider.myServices.length > 0) {
            // Update existing service
            const matchedService = provider.myServices.find((service) => {
              if (service.serviceName === editService.serviceName) {
                return service;
              }
            });
            if (matchedService) {
              matchedService.amount = editService.amount;
              matchedService.details = editService.details;
              matchedService.title = editService.title;
              if (
                matchedService.selectedFileURL !== editService.selectedFileURL
              ) {
                matchedService.selectedFileURL = editService.selectedFileURL;
              }
              const restServices = provider.myServices.filter((service) => {
                if (service.serviceName !== editService.serviceName) {
                  return service;
                }
              });

              const result = await providersCollection.findOneAndUpdate(
                { uid: providerId },
                { $set: { myServices: [...restServices, matchedService] } },
                { returnOriginal: false }
              );

              return res.send(result);
            } else {
              const restServices = provider.myServices.filter((service) => {
                if (service.serviceName !== editService.serviceName) {
                  return service;
                }
              });
              const result = await providersCollection.findOneAndUpdate(
                { uid: providerId },
                { $set: { myServices: [...restServices, editService] } },
                { returnOriginal: false }
              );
              return res.send(result);
            }
          }
          // res.json(result.value);
          else {
            // Create new service array
            const result = await providersCollection.findOneAndUpdate(
              { uid: providerId },
              { $set: { myServices: [editService] } },
              { returnOriginal: false }
            );
            return res.json(result);
          }
        } else {
          res.status(404).json({ error: "Provider not found" });
        }
      } catch (error) {
        console.error("Error updating provider service:", error);
        res.status(500).json({ error: "Internal server error" });
      }
    });

    app.post("/provider-service/:providerId", async (req, res) => {
      const providerId = req.params.providerId;
      const { serviceName } = req.body;
      const provider = await providersCollection.findOne({ uid: providerId });
      if (provider?.myServices) {
        const matchedService = provider.myServices.find(
          (service) => service.serviceName === serviceName
        );
        return res.send(matchedService);
      }
      res.send({});
    });

    const tran_id = new ObjectId().toString();

    app.post("/make-payment", async (req, res) => {
      const bookingInfo = req.body;
      const booking = await bookingCollection.findOne({
        _id: new ObjectId(bookingInfo._id),
      });

      // const data = {
      //   total_amount: booking.totalAmount,
      //   quantity: booking.serviceQuantity,
      //   currency: "BDT",
      //   tran_id: tran_id, // use unique tran_id for each api call
      //   success_url: "http://localhost:3030/success",
      //   fail_url: "http://localhost:3030/fail",
      //   cancel_url: "http://localhost:3030/cancel",
      //   ipn_url: "http://localhost:3030/ipn",
      //   booking_data: bookingInfo.selectedDate,
      //   service_name: bookingInfo.service,
      //   provider_uid: bookingInfo.serviceManUID,
      //   provider_name: bookingInfo.providerName,
      //   provider_phone: bookingInfo.providerPhone,
      //   provider_photo: bookingInfo.providerPhotoURL,
      //   cus_name: bookingInfo.userName,
      //   cus_photo: bookingInfo.userPhotoURL,
      //   cus_uid: bookingInfo.userUID,
      //   cus_division: bookingInfo.division,
      //   cus_district: bookingInfo.district,
      //   cus_upazila: bookingInfo.upazila,
      //   cus_fullAddress: bookingInfo.fullAddress,
      //   cus_country: "Bangladesh",
      //   cus_phone: bookingInfo.userPhone,
      //   booking_status: bookingInfo.bookingStatus,
      // };

      // console.log(data);

      const data = {
        total_amount: booking.totalAmount,
        currency: "BDT",
        tran_id: tran_id, // use unique tran_id for each api call
        success_url: `https://subidha-home-services-server3792.glitch.me/payment/success/${booking._id}`,
        fail_url: "http://localhost:3030/fail",
        cancel_url: "http://localhost:3030/cancel",
        ipn_url: "http://localhost:3030/ipn",
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

      console.log(data);

      const sslcz = new SSLCommerzPayment(store_id, store_passwd, is_live);
      sslcz.init(data).then((apiResponse) => {
        // Redirect the user to payment gateway
        let GatewayPageURL = apiResponse.GatewayPageURL;
        res.send({ url: GatewayPageURL });

        // console.log("Redirecting to: ", GatewayPageURL);
      });

      const payment = {
        bookingId: booking._id,
        bookingDetails: booking,
        paidStatus: false,
        transationId: tran_id,
      };

      const result = await paymentCollection.insertOne(payment);

      app.post("/payment/success/:bookingId", async (req, res) => {
        console.log(req.params.bookingId);
        const paymentUpdateResult = await paymentCollection.updateOne(
          {
            bookingId: new ObjectId(req.params.bookingId),
          },
          {
            $set: {
              paidStatus: true,
            },
          }
        );

        const bookingUpdateResult = await bookingCollection.updateOne(
          { _id: new ObjectId(req.params.bookingId) },
          {
            $set: {
              paidStatus: true,
            },
          }
        );

        if (
          paymentUpdateResult.modifiedCount > 0 &&
          bookingUpdateResult.modifiedCount > 0
        ) {
          res.redirect(`http://localhost:5173/payment/success/${req.params.bookingId}`);
        }
      });
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
