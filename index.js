const express = require('express');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const cors = require('cors');
require('dotenv').config();

const app = express();

// middleware
app.use(cors());
app.use(express.json());

const port = process.env.PORT || 5000;

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASSWORD}@cluster0.5f5xb9l.mongodb.net/?retryWrites=true&w=majority`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

async function run() {
  const allServicesCollection = client.db('SubidhaHomeService').collection('services');
  try {
    app.get('/allServiceCategories', async (req, res) => {
      try {
        const query = {};
        const serviceCategories = await allServicesCollection.find(query).toArray();
        const allServiceCategory = serviceCategories.map(serviceCategory => ({
          _id: serviceCategory._id,
          serviceName: serviceCategory.serviceName,
          icon: serviceCategory.icon,
          totalService: serviceCategory.subCategories.length
        }));
        console.log(allServiceCategory.length);
        console.log(allServiceCategory);
        res.send(allServiceCategory);
      } catch (error) {
        console.error(error);
        res.status(500).send('Internal Server Error');
      }
    });

    app.get('/allServiceCategories/:id', async(req, res) => {
        try {
          const serviceId = req.params.id;
          console.log(serviceId)
          const query = {
            _id: new ObjectId(serviceId),
          }
          const service = await allServicesCollection.findOne(query);
          res.send(service);
        } catch(error) {
          console.log(error);
          res.status(500).send('Internal Server Error');
        }

    });

    app.get('/subcategory/:categoryId/:subCategoryId', async (req, res) => {
      try {
        const categoryId = req.params.categoryId;
        const subCategoryId = req.params.subCategoryId;

        console.log(categoryId);
        console.log(subCategoryId);
        
        const query = {
          _id: new ObjectId(categoryId),
        }
        const serviceCategory = await allServicesCollection.findOne(query);
    
        if (!serviceCategory) {
          return res.status(404).send('Service category not found');
        }
        
        const subCategory = serviceCategory.subCategories.find(subCategory => subCategory.id === subCategoryId);
    
        if (!subCategory) {
          return res.status(404).send('Subcategory not found');
        }
    
        res.send({
          subCategory,
          serviceOverview: serviceCategory.serviceOverview,
          faq: serviceCategory.faq
        });
      } catch (error) {
        console.error(error);
        res.status(500).send('Internal Server Error');
      }
    });
    
    
    console.log("Pinged your deployment. You successfully connected to MongoDB!");
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);


app.get('/', (req, res) => {
  res.send('Subidha Home Service Server is Running...');
});

app.listen(port, () => {
  console.log(`Home Services Server app Listening on Port: ${port}`);
});

