# Vercel Deployment Guide for Subidha Home Services Backend

## Environment Variables Required

You need to set the following environment variables in your Vercel project dashboard:

### Required Environment Variables:

1. **MONGODB_URI** - Your MongoDB connection string

   ```
   mongodb+srv://username:password@cluster.mongodb.net/database_name?retryWrites=true&w=majority
   ```

2. **FIREBASE_PROJECT_ID** - Your Firebase project ID

   ```
   your-firebase-project-id
   ```

3. **IMAGEBB_API_KEY** - ImageBB API key for image uploads

   ```
   your-imagebb-api-key
   ```

4. **EMAIL_USER** - Email address for sending emails

   ```
   your-email@domain.com
   ```

5. **EMAIL_PASS** - Email password or app password
   ```
   your-email-password
   ```

### Optional Environment Variables:

6. **SSLCOMMERZ_STORE_ID** - SSLCommerz store ID for payments
7. **SSLCOMMERZ_STORE_PASSWORD** - SSLCommerz store password
8. **TWILIO_ACCOUNT_SID** - Twilio account SID for SMS
9. **TWILIO_AUTH_TOKEN** - Twilio auth token
10. **TWILIO_PHONE_NUMBER** - Twilio phone number
11. **JWT_SECRET** - JWT secret for authentication tokens

## Deployment Steps:

1. Install Vercel CLI:

   ```bash
   npm i -g vercel
   ```

2. Login to Vercel:

   ```bash
   vercel login
   ```

3. Navigate to your backend project directory:

   ```bash
   cd subidha_home_service_server
   ```

4. Deploy to Vercel:

   ```bash
   vercel
   ```

5. Follow the prompts to link your project to a Vercel project

6. Set environment variables in Vercel dashboard:

   - Go to your project in Vercel dashboard
   - Navigate to Settings > Environment Variables
   - Add all the required environment variables listed above

7. Redeploy to apply environment variables:
   ```bash
   vercel --prod
   ```

## Important Notes:

- The serverless function timeout is set to 30 seconds in vercel.json
- All routes are configured to point to index.js
- The build process uses @vercel/node runtime
- Make sure your MongoDB connection string allows connections from Vercel's IP ranges
- Firebase Admin SDK will use default credentials in production

## Troubleshooting:

- If you get timeout errors, consider optimizing your database queries
- Check Vercel function logs for detailed error messages
- Ensure all environment variables are properly set
- Verify MongoDB connection allows external connections

