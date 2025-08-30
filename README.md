# 🔍 **Swagger API Tester - Burp Suite Extension**

A comprehensive Burp Suite extension for parsing Swagger/OpenAPI specifications and testing API endpoints with advanced features including bulk testing, keyboard shortcuts, and seamless Burp integration.

## 🚀 **Features**

### **Core Functionality**
- **Swagger/OpenAPI Parsing** - Support for JSON and YAML formats
- **Interactive API Testing** - Repeater-like interface for endpoint testing
- **Bulk Testing** - Test all endpoints automatically with configurable delays
- **Parameter Management** - Dynamic path, query, and header parameter handling
- **Authentication Support** - Bearer Token, API Key, Basic Auth, and Custom Headers
- **Base URL Management** - Dynamic URL switching and environment variations

### **Advanced Testing Features**
- **Bulk Testing Tab** - Automatically test all endpoints sequentially
- **Export Functionality** - Export test results in customizable chunks
- **Status Code Filtering** - Filter export results by HTTP status codes
- **Result Sorting** - Sort bulk testing results by any column
- **Pause/Resume/Restart** - Control bulk testing execution

### **Burp Suite Integration**
- **Context Menu Integration** - Right-click options throughout Burp Suite
- **Tool Integration** - Send requests to Repeater, Intruder, Scanner, and Comparer
- **Keyboard Shortcuts** - Quick access to common actions
- **Seamless Workflow** - Works alongside existing Burp tools

### **User Experience**
- **Syntax Highlighting** - Burp Suite-style color coding for requests/responses
- **Theme Support** - Burp theme and dark theme options
- **Endpoint List** - Clear, organized view of all available endpoints
- **Real-time Updates** - Immediate synchronization between tabs
- **Endpoint Management** - Remove single or multiple endpoints with confirmation dialogs

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
- Click **"Load from File"** and select your Swagger JSON/YAML file
- Or enter Swagger URL and click **"Fetch from URL"**
- View parsed endpoints in the table

### **2. Test Individual Endpoints**
- Go to **"API Tester"** tab
- Select endpoint from the organized list
- Modify parameters and headers as needed
- Use **Ctrl+Space** (**⌃+Space**) to send request

### **3. Bulk Test All Endpoints**
- Go to **"Bulk Testing"** tab
- Configure delay and timeout settings
- Click **"Start Bulk Testing"** to test all endpoints
- Monitor progress and results in real-time

---

## 🎯 **Detailed Usage Guide**

### **Import Swagger Tab**

#### **Loading Specifications**
- **From File**: Click "Load from File" → Select JSON/YAML file → Automatic parsing
- **From URL**: Enter Swagger URL → Click "Fetch from URL" → Automatic parsing
- **File Validation**: Only accepts `.json`, `.yaml`, and `.yml` files
- **Auto-Update**: All tabs update automatically after successful loading

#### **Features**
- **Parsed Endpoints Table**: Shows Method, Path, Tags, and Description
- **Base URL Management**: Automatically extracts and displays base URL
- **Specification Info**: Displays API metadata, version, and details
- **Progress Tracking**: Shows loading progress and endpoint count

### **API Tester Tab**

#### **Endpoint Selection**
- **Organized List**: All endpoints displayed with method and path
- **Search & Filter**: Find specific endpoints quickly
- **Tag Filtering**: Filter by API tags/categories

#### **Request Building**
- **Method Selection**: GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD
- **URL Construction**: Automatic path parameter substitution
- **Parameter Management**: 
  - **Path Parameters**: Required parameters in URL path
  - **Query Parameters**: Optional parameters in URL query string
  - **Header Parameters**: Custom headers for the request
- **Body Content**: JSON/XML body for POST/PUT requests

#### **Response Analysis**
- **Status Code**: HTTP response status
- **Response Headers**: All response headers displayed
- **Response Body**: Formatted and syntax-highlighted
- **Response Time**: Request execution time
- **Size Information**: Response size in bytes

#### **Quick Actions**
- **Pretty Print**: Format JSON/XML responses
- **Minify**: Compress response content
- **Syntax Highlighting**: Color-coded content
- **Theme Switching**: Burp theme or dark theme

#### **Endpoint Management**
- **Remove Selected**: Remove the currently selected endpoint
- **Remove Multiple**: Remove multiple selected endpoints at once
- **Clear All**: Remove all endpoints from the list
- **Context Menu**: Right-click on endpoints for quick actions
- **Copy Endpoint Info**: Copy endpoint details to clipboard
- **Bulk Operations**: Select multiple endpoints for batch removal

### **Bulk Testing Tab**

#### **Configuration**
- **Delay Setting**: Time between requests (milliseconds)
- **Timeout Setting**: Maximum time to wait for each response (milliseconds)
- **Endpoint Selection**: Choose which endpoints to test
- **Timeout Handling**: Automatic timeout detection with visual indicators

#### **Execution Control**
- **Start**: Begin bulk testing process
- **Pause**: Temporarily pause testing
- **Resume**: Continue from where you left off
- **Stop**: Completely stop testing
- **Restart**: Stop and restart from beginning
- **Clear Results**: Clear all test results

#### **Progress Monitoring**
- **Progress Bar**: Visual indication of completion
- **Status Display**: Current status (Running, Paused, Stopped)
- **Endpoint Counter**: Shows current endpoint being tested
- **Real-time Updates**: Live updates during execution

#### **Results Management**
- **Results Table**: Shows all test results with columns:
  - Status (Success/Error/Timeout)
  - Method
  - Path
  - Response Code
  - Response Time
  - Size
  - Notes
- **Status Colors**: 
  - 🟢 **Green**: Successful responses
  - 🔴 **Red**: Error responses
  - 🟡 **Yellow**: Timeout responses
- **Sorting**: Click any column header to sort results
- **Context Menu**: Right-click for additional options

#### **Export Functionality**
- **Chunk Size**: Number of unique APIs per export file
- **Export Types**:
  - **Full Results**: Complete requests and responses
  - **API List Only**: Just the list of APIs with methods
  - **Requests Only**: Only the HTTP requests
  - **Responses Only**: Only the HTTP responses
- **Status Filtering**: Filter by specific HTTP status codes
- **File Naming**: Automatic naming based on base URL
- **Content Format**: Straight column format for API lists

### **Settings Tab**

#### **Authentication Profiles**
- **Bearer Token**: Simple token-based authentication
- **API Key**: Custom header name and value
- **Basic Auth**: Username and password authentication
- **Custom Headers**: User-defined authentication headers
- **Profile Management**: Save, load, edit, and delete profiles

#### **Global Headers**
- **Header Override**: Set headers that override endpoint-specific ones
- **Custom Headers**: Add headers for all requests
- **Header Management**: Add, edit, and remove global headers

#### **Theme Settings**
- **Burp Theme**: Matches Burp Suite's default appearance
- **Dark Theme**: Alternative dark color scheme
- **Syntax Highlighting**: Color-coded request/response elements

---

## ⌨️ **Keyboard Shortcuts**

### **Request Actions**
- **Ctrl+Space** (**⌃+Space**): Send request to API
- **Ctrl+R** (**⌃+R**): Send request to Repeater
- **Ctrl+I** (**⌃+I**): Send request to Intruder
- **Ctrl+O** (**⌃+O**): Send request to Organizer/Scanner

### **Endpoint Management**
- **Delete**: Remove selected endpoint(s) from the list
- **Ctrl+Delete**: Clear all endpoints from the list

### **Usage Notes**
- Shortcuts work when an endpoint is selected in API Tester tab
- All shortcuts are configurable and reliable
- Works with Windows/Linux/MacOS systems

---

## 🔧 **Configuration & Customization**

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
- **Bulk Security Scanning** - Test all endpoints for common vulnerabilities

### **Development & QA**
- **API Testing** - Functional testing of API endpoints
- **Documentation Testing** - Verify API specification accuracy
- **Integration Testing** - Test API interactions and workflows
- **Performance Testing** - Test API response times and limits
- **Regression Testing** - Ensure changes don't break existing functionality

### **Security Research**
- **Vulnerability Research** - Discover new attack vectors
- **Security Tool Development** - Build custom testing tools
- **Security Training** - Learn API security testing techniques
- **Compliance Testing** - Verify security requirements

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
- **Bulk Testing** - Comprehensive endpoint coverage

---

## 📊 **Export & Reporting**

### **Export Options**
- **Chunked Export**: Split large results into manageable files
- **Status Filtering**: Export only specific HTTP status codes
- **Content Selection**: Choose what to export (requests, responses, or both)
- **File Naming**: Automatic naming based on base URL and chunk number

### **Export Formats**
- **API List**: Clean, organized list of endpoints with HTTP methods
- **Request Details**: Complete HTTP requests with headers and body
- **Response Details**: Complete HTTP responses with status and content
- **Metadata**: Export information including date, filter settings, and counts

---

## 🔮 **Advanced Features**

### **Bulk Testing Capabilities**
- **Sequential Execution**: Test endpoints one by one with configurable delays
- **State Management**: Pause, resume, and restart testing at any time
- **Progress Tracking**: Real-time progress updates and status information
- **Result Analysis**: Comprehensive results with sorting and filtering
- **Export Management**: Flexible export options for analysis and reporting

### **Parameter Handling**
- **Dynamic Parameter Detection**: Automatically detect required and optional parameters
- **Parameter Merging**: Combine path-level and method-level parameters
- **Type Support**: Handle various parameter types (string, integer, boolean, array)
- **Example Generation**: Generate realistic example values for testing

### **Header Management**
- **Smart Header Override**: Global headers properly override endpoint-specific ones
- **Content-Type Handling**: Automatic content-type detection and setting
- **Authentication Headers**: Automatic inclusion of authentication headers
- **Custom Header Support**: Add any custom headers needed for testing

---

## 🚨 **Troubleshooting**

### **Common Issues**

#### **File Loading Problems**
- **Issue**: "0 endpoints loaded" after file selection
- **Solution**: Ensure file is valid JSON/YAML Swagger specification
- **Check**: File extension (.json, .yaml, .yml) and content format

#### **Bulk Testing Issues**
- **Issue**: Bulk testing buttons not visible
- **Solution**: Check if endpoints are loaded first
- **Check**: Ensure bulk testing tab is properly initialized

#### **Keyboard Shortcuts Not Working**
- **Issue**: Shortcuts don't respond
- **Solution**: Ensure endpoint is selected in API Tester tab
- **Check**: Verify shortcuts are properly configured

#### **Export Failures**
- **Issue**: Export creates empty files
- **Solution**: Ensure bulk testing has completed with results
- **Check**: Verify chunk size and filter settings

### **Debug Information**
- **Console Output**: Check Burp Suite console for detailed logs
- **Error Messages**: Look for specific error popups
- **Status Indicators**: Monitor progress bars and status labels

---

## 📄 **License**

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🔗 **Support & Community**

### **Getting Help**
- **Documentation**: This README provides comprehensive usage information
- **Console Logs**: Check Burp Suite console for detailed operation logs
- **Error Messages**: Look for specific error popups with troubleshooting hints

### **Feature Requests**
- **Bulk Testing**: Already implemented with pause/resume/restart
- **Export Functionality**: Already implemented with flexible options
- **Keyboard Shortcuts**: Already implemented for quick access
- **Advanced Authentication**: Already implemented with profile management

---

*This extension transforms Burp Suite into a **powerful API testing platform**, providing comprehensive Swagger/OpenAPI support with advanced bulk testing capabilities, seamless integration into your existing security testing workflow, and professional-grade export and reporting features.*
