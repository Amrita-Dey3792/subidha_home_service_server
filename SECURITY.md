# 🔒 Security Guide

## Environment Variables Protection

This backend is configured to use environment variables for all sensitive information to ensure security when deployed to public repositories.

### 🚨 Critical Security Measures

1. **No Hardcoded Credentials** - All sensitive data moved to environment variables
2. **Environment Validation** - Server won't start without required variables
3. **Git Protection** - .env files are gitignored
4. **Template Provided** - env.example shows required variables

### 📋 Required Environment Variables

| Variable              | Description                     | Security Level |
| --------------------- | ------------------------------- | -------------- |
| `MONGODB_URI`         | Database connection string      | 🔴 Critical    |
| `FIREBASE_PROJECT_ID` | Firebase project identifier     | 🟡 Medium      |
| `IMAGEBB_API_KEY`     | Image upload service key        | 🟡 Medium      |
| `EMAIL_USER`          | Gmail account for notifications | 🔴 Critical    |
| `EMAIL_PASS`          | Gmail app password              | 🔴 Critical    |
| `STORE_ID`            | SSL Commerz store ID            | 🔴 Critical    |
| `STORE_PASSWORD`      | SSL Commerz store password      | 🔴 Critical    |

### 🛡️ Security Features

- **Environment Validation**: Server validates all required variables on startup
- **Graceful Failure**: Clear error messages for missing variables
- **No Fallbacks**: No hardcoded fallback values in production
- **Git Protection**: Comprehensive .gitignore prevents accidental commits

### 🚀 Deployment Security

1. **Local Development**: Use .env file with actual values
2. **Production**: Set environment variables in hosting platform
3. **Never Commit**: .env files are automatically ignored by git
4. **Rotate Keys**: Regularly update API keys and passwords

### ⚠️ Important Notes

- Change all default passwords before production use
- Use strong, unique passwords for all services
- Regularly rotate API keys and credentials
- Monitor access logs for suspicious activity
- Enable 2FA where possible

### 🔧 Setup Instructions

1. Copy `env.example` to `.env`
2. Fill in your actual values
3. Never commit the `.env` file
4. Set environment variables in production

This ensures your sensitive information remains secure even in public repositories.
