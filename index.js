const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const SSLCommerzPayment = require("sslcommerz-lts");
const jwt = require("jsonwebtoken");
const express = require("express");
const http = require("http");
const socketIo = require("socket.io");
const cors = require("cors");
const nodemailer = require("nodemailer");
const { Reject } = require("twilio/lib/twiml/VoiceResponse");
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

    // const tran_id = new ObjectId().toString();

    function generateTransactionId() {
      const tran_id = new ObjectId().toString();
      return tran_id;
    }

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
        tran_id: generateTransactionId(), // use unique tran_id for each api call
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
        bookingId: bookingInfo._id,
        bookingDetails: booking,
        paidStatus: false,
        transationId: tran_id,
      };

      const options = { upsert: true };

      const result = await paymentCollection.findOneAndUpdate(
        {
          bookingId: bookingInfo._id,
        },
        { $set: payment },
        options
      );

      app.post("/payment/success/:bookingId", async (req, res) => {
        console.log(req.params.bookingId);
        const paymentUpdateResult = await paymentCollection.updateOne(
          {
            bookingId: req.params.bookingId,
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
          res.redirect(
            `http://localhost:5173/payment/success/${req.params.bookingId}`
          );
        }
      });
    });

    app.get("/payment/:transationId", async (req, res) => {
      const transationId = req.params.transationId;
      console.log("Transaction Id", transationId);
      const query = {
        transationId,
      };

      const payment = await paymentCollection.findOne(query);
      console.log(payment);

      res.send(payment);
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
          <p style="font-size: 14px; line-height: 140%;"><span style="font-size: 16px; line-height: 22.4px;"><span style="font-size: 16px; line-height: 22.4px;">BDT <strong style="color: #595959;">BDT ${totalAmount}</strong></span></span></p>
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
