# Subidha Home Services - Backend API

A comprehensive backend API for home services management platform built with Node.js, Express, and MongoDB.

## 🚀 Features

- **User Authentication** - Firebase Auth integration
- **Service Management** - CRUD operations for services
- **Provider Management** - Service provider registration and management
- **Payment Integration** - SSL Commerz payment gateway
- **Email Notifications** - Automated email system
- **File Upload** - Image upload with ImageBB
- **Real-time Communication** - Socket.io integration

## 📋 Prerequisites

- Node.js (v14 or higher)
- MongoDB Atlas account
- Firebase project
- SSL Commerz account
- ImageBB API key
- Gmail account for email service

## 🛠️ Installation

1. **Clone the repository**

   ```bash
   git clone <repository-url>
   cd subidha-home-services-server
   ```

2. **Install dependencies**

   ```bash
   npm install
   ```

3. **Environment Setup**

   ```bash
   cp env.example .env
   ```

   Update the `.env` file with your actual values:

   - MongoDB connection string
   - Firebase project credentials
   - SSL Commerz credentials
   - ImageBB API key
   - Email configuration

4. **Start the server**
   ```bash
   npm start
   ```

## 🔧 Environment Variables

| Variable              | Description                          | Required |
| --------------------- | ------------------------------------ | -------- |
| `MONGODB_URI`         | MongoDB connection string            | ✅       |
| `FIREBASE_PROJECT_ID` | Firebase project ID                  | ✅       |
| `STORE_ID`            | SSL Commerz store ID                 | ✅       |
| `STORE_PASSWORD`      | SSL Commerz store password           | ✅       |
| `IMAGEBB_API_KEY`     | ImageBB API key                      | ✅       |
| `EMAIL_USER`          | Gmail address                        | ✅       |
| `EMAIL_PASS`          | Gmail app password                   | ✅       |
| `PORT`                | Server port (default: 5000)          | ❌       |
| `NODE_ENV`            | Environment (development/production) | ❌       |

## 📚 API Endpoints

### Authentication

- `POST /register` - User registration
- `POST /login` - User login
- `GET /check-user-status/:uid` - Check user status

### Services

- `GET /services` - Get all services
- `POST /services` - Create new service
- `PUT /services/:id` - Update service
- `DELETE /services/:id` - Delete service

### Providers

- `GET /providers` - Get all providers
- `POST /providers` - Register new provider
- `PUT /providers/:id` - Update provider
- `DELETE /providers/:id` - Delete provider

### Payments

- `POST /payment` - Process payment
- `POST /payment/success` - Payment success callback
- `POST /payment/fail` - Payment failure callback

## 🔒 Security

- All sensitive information is stored in environment variables
- Never commit `.env` files to version control
- Use strong passwords and API keys
- Regularly rotate credentials

## 📝 License

This project is licensed under the ISC License.

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📞 Support

For support, email support@subidhahomeservice.com
