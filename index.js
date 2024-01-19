const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const express = require("express");
const http = require("http");
const socketIo = require("socket.io");
const cors = require("cors");
require("dotenv").config();

const app = express();

const server = http.createServer(app);

const io = socketIo(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"],
  },
});

// middleware
app.use(express.json());
app.use(cors());

const port = process.env.PORT || 5000;

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
  const providersCollection = client.db("SubidhaHomeService").collection("providers");

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
        console.log(serviceId);
        const query = {
          _id: new ObjectId(serviceId),
        };
        const service = await allServicesCollection.findOne(query);
        res.send(service);
      } catch (error) {
        console.log(error);
        res.status(500).send("Internal Server Error");
      }
    });

    app.get("/subcategory/:categoryId/:subCategoryId", async (req, res) => {
      try {
        const categoryId = req.params.categoryId;
        const subCategoryId = req.params.subCategoryId;

        console.log(categoryId);
        console.log(subCategoryId);

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
          subCategory,
          serviceOverview: serviceCategory.serviceOverview,
          faq: serviceCategory.faq,
        });
      } catch (error) {
        console.error(error);
        res.status(500).send("Internal Server Error");
      }
    });

    app.get("/users", async (req, res) => {
      try {
        const searchTerm = req.query.searchText;
        const page = req.query.page;
        const size = req.query.size;
        if (searchTerm) {
          let users = await usersCollection.find().toArray();
          users = users?.filter((user) => {
            console.log(user?.userName);
            console.log(searchTerm);

            // console.log(user.phone?.toLowerCase().includes(searchTerm.toLowerCase()) > -1)
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

    app.get("/users/:uid", async(req, res) => {
      try {
        const uid = req.params.uid;
        const query = {
          uid
        }
        const user = await usersCollection.findOne(query);
        res.send(user);
        
      } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Internal server error" });
      }
    });

    app.post("/users/:uid", async(req, res) => {
      try {
        const data = req.body;
        const uid = req.params.uid;

        const filter = {
          uid
        }

        const options = { upsert: true };

        const updateDoc = {
          $set: {
            [Object.keys(data)[0]]: Object.values(data)[0]
          },
        };
        const result = await usersCollection.updateOne(filter, updateDoc, options);
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
        result = await usersCollection.updateOne(filter, updateDoc, options);
        res.send(result);
      } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Internal server error" });
      }
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

    app.get("/chats/:roomId", async (req, res) => {
      const roomId = req.params.roomId;
      const query = {
        roomId,
      };
      const result = await messageCollection.findOne(query);
      if (result) {
        res.send(result);
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
