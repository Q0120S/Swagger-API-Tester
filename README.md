# 🔍 **Swagger API Tester - Burp Suite Extension**

A comprehensive Burp Suite extension for parsing Swagger/OpenAPI specifications and testing API endpoints with a powerful, user-friendly interface.

## 🚀 **Features**

### **Core Functionality**
- **Swagger/OpenAPI Parsing** - Support for JSON and YAML formats
- **Interactive API Testing** - Repeater-like interface for endpoint testing
- **Parameter Management** - Dynamic path, query, and header parameter handling
- **Authentication Support** - Bearer Token, API Key, Basic Auth, and Custom Headers
- **Base URL Management** - Dynamic URL switching and environment variations

### **Burp Suite Integration**
- **Context Menu Integration** - Right-click options throughout Burp Suite
- **Tool Integration** - Send requests to Repeater, Intruder, Scanner, and Comparer
- **Export Functionality** - Save requests as curl commands or files
- **Seamless Workflow** - Works alongside existing Burp tools

### **User Experience**
- **Syntax Highlighting** - Burp Suite-style color coding for requests/responses
- **Theme Support** - Burp theme and dark theme options
- **Endpoint List** - Clear, organized view of all available endpoints
- **Real-time Updates** - Immediate synchronization between tabs

---

## 🛠️ **Installation**

### **Prerequisites**
- **Burp Suite Professional** (Community Edition may have limitations)
- **Jython 2.7** (included with Burp Suite)

### **Installation Steps**
1. Download `swagger_api_tester.py`
2. In Burp Suite, go to **Extensions** → **Installed**
3. Click **Add** → **Extension type: Python**
4. Select the file and click **Next** → **Close**
5. The extension will appear as a new tab: **"Swagger API Tester"**

---

## 🚀 **Quick Start**

### **1. Load OpenAPI Specification**
- Go to **"Import Swagger"** tab
- Enter Swagger URL or load from file
- View parsed endpoints in the table

### **2. Test API Endpoints**
- Go to **"API Tester"** tab
- Select endpoint from the organized list
- Modify parameters and headers as needed
- Click **"Send Request"**

### **3. Advanced Testing**
- Right-click requests for context menu options
- Send to Burp tools (Repeater, Intruder, Scanner)
- Export requests and responses
- Customize themes and highlighting

---

## 🎯 **Usage Examples**

### **Basic API Testing**
```
1. Load OpenAPI spec from https://petstore.swagger.io/v2/swagger.json
2. Select /pet/{petId} endpoint from the list
3. Set petId parameter to "1"
4. Click "Send Request"
5. Review response and modify as needed
```

### **Authentication Testing**
```
1. Go to "Settings" tab
2. Select authentication type (Bearer Token, API Key, etc.)
3. Enter credentials
4. Authentication headers are automatically applied to all requests
```

### **Parameter Management**
```
1. Select an endpoint with parameters
2. Modify path, query, and header parameters
3. Use "Update Request" to rebuild the request
4. Send the modified request
```

---

## 🎨 **Interface Overview**

### **Import Swagger Tab**
- **URL Input**: Enter Swagger/OpenAPI specification URLs
- **File Upload**: Load specifications from local files
- **Parsed Endpoints Table**: View all available endpoints
- **Base URL Management**: Set and modify the base URL
- **Specification Info**: Display API metadata and details

### **API Tester Tab**
- **Endpoint List**: Organized list of all available endpoints
- **Request Builder**: Method, URL, content-type, and body editor
- **Parameter Management**: Path, query, and header parameters
- **Response Viewer**: Display and analyze API responses
- **Quick Actions**: Pretty print, minify, highlight, theme switching

### **Settings Tab**
- **Authentication**: Bearer Token, API Key, Basic Auth, Custom Headers
- **Global Headers**: Add custom headers for all requests
- **Theme Selection**: Choose between Burp and dark themes

---

## 🔧 **Configuration**

### **Base URL Management**
- **Import Tab**: Set the primary base URL for the API
- **API Tester Tab**: Quick base URL switching with common variations
- **Auto-sync**: Changes in one tab automatically update the other

### **Authentication Setup**
- **Bearer Token**: Simple token-based authentication
- **API Key**: Custom header name and value
- **Basic Auth**: Username and password authentication
- **Custom Headers**: User-defined authentication headers

### **Theme Customization**
- **Burp Theme**: Matches Burp Suite's default appearance
- **Dark Theme**: Alternative dark color scheme
- **Syntax Highlighting**: Color-coded request/response elements

---

## 🎯 **Use Cases**

### **API Security Testing**
- **Vulnerability Assessment** - Identify security weaknesses in APIs
- **Penetration Testing** - Systematic security testing of endpoints
- **Authentication Testing** - Test various auth mechanisms
- **Input Validation Testing** - Test parameter handling and validation

### **Development & QA**
- **API Testing** - Functional testing of API endpoints
- **Documentation Testing** - Verify API specification accuracy
- **Integration Testing** - Test API interactions and workflows
- **Performance Testing** - Test API response times and limits

### **Security Research**
- **Vulnerability Research** - Discover new attack vectors
- **Security Tool Development** - Build custom testing tools
- **Security Training** - Learn API security testing techniques

---

## 🛡️ **Security Features**

### **Authentication Testing**
- **Bearer Token Validation** - Test token-based authentication
- **API Key Security** - Verify API key handling
- **Basic Auth Testing** - Test username/password authentication
- **Custom Header Security** - Test custom authentication schemes

### **Input Validation Testing**
- **Parameter Manipulation** - Test path, query, and header parameters
- **Content-Type Testing** - Test various request formats
- **Body Parameter Testing** - Test request body validation
- **Header Injection Testing** - Test header parameter handling

### **Integration Testing**
- **Burp Tool Integration** - Send requests to Repeater, Intruder, Scanner
- **Context Menu Actions** - Right-click options throughout Burp Suite
- **Export Functionality** - Save requests as curl commands or files

---

## 🔮 **Future Roadmap**

### **Short Term (1-3 months)**
- [ ] **Enhanced Parameter Handling** - Better parameter type detection
- [ ] **Request Templates** - Save and reuse request configurations
- [ ] **Response Analysis** - Enhanced response parsing and validation
- [ ] **Performance Improvements** - Faster endpoint parsing and loading

### **Medium Term (3-6 months)**
- [ ] **Test Collections** - Organize and manage test scenarios
- [ ] **Automated Testing** - Basic automated test execution
- [ ] **Reporting Features** - Generate test reports and summaries
- [ ] **Advanced Authentication** - OAuth, JWT, and other auth schemes

### **Long Term (6+ months)**
- [ ] **Multi-API Support** - Test multiple APIs simultaneously
- [ ] **Advanced Analytics** - Testing metrics and performance analysis
- [ ] **Collaborative Testing** - Team-based testing workflows
- [ ] **Enterprise Features** - Role-based access, audit logging

---

## 📄 **License**

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🎉 **Get Started Today**

Transform your API testing workflow with **comprehensive Swagger support** and **seamless Burp integration**:

1. **Install the extension** in Burp Suite
2. **Load your Swagger specification** (JSON or YAML)
3. **Start testing endpoints** with the intuitive interface
4. **Integrate with Burp tools** for advanced testing

**🚀 Start testing your APIs with professional-grade tools!**

---

*This extension transforms Burp Suite into a **powerful API testing platform**, providing comprehensive Swagger/OpenAPI support with seamless integration into your existing security testing workflow.*
