#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Swagger API Tester - Burp Extension
A comprehensive Burp extension for parsing Swagger/OpenAPI specifications
and testing API endpoints with a repeater-like interface.

Author: Based on autoswagger project
Version: 1.0.0
"""

from burp import IBurpExtender, ITab, IHttpListener, IMessageEditorController, IContextMenuFactory
from javax.swing import (JPanel, JTabbedPane, JScrollPane, JTextArea, JButton, 
                        JTextField, JLabel, JComboBox, JSplitPane, JTable, 
                        DefaultComboBoxModel, JFileChooser, JOptionPane, 
                        SwingConstants, JProgressBar, JCheckBox, GroupLayout,
                        LayoutStyle, BorderFactory, JList, DefaultListModel,
                        ListSelectionModel, JTextPane, JPopupMenu, JMenuItem)
from javax.swing.event import ListSelectionListener, DocumentListener
from javax.swing.table import DefaultTableModel, AbstractTableModel
from javax.swing.border import TitledBorder
from javax.swing.text import SimpleAttributeSet, StyleConstants, StyledDocument, DefaultStyledDocument
from javax.swing.text.html import HTMLEditorKit
from java.awt import BorderLayout, GridBagLayout, GridBagConstraints, Insets, Font, Color, Dimension
from java.awt.event import ActionListener, MouseAdapter
from java.net import URL, HttpURLConnection
from java.io import BufferedReader, InputStreamReader, ByteArrayOutputStream, File as JavaFile
import java.lang.Thread as JavaThread
from threading import Thread
import json
import re

# Try to import yaml, fallback to yaml_lite if not available
try:
    import yaml
except ImportError:
    try:
        import yaml_lite as yaml
    except ImportError:
        yaml = None
import os
import sys
import time
from urlparse import urlparse, urljoin, parse_qs
from urllib import urlencode
import base64

from collections import OrderedDict

class SyntaxHighlighter:
    """Syntax highlighter for HTTP requests/responses and JSON/XML"""
    
    def __init__(self):
        self.current_theme = "burp"
        self._initializeThemes()
        self._applyTheme()
    
    def _initializeThemes(self):
        """Initialize color themes"""
        # Burp Suite Repeater theme
        self.burp_theme = {
            'method': Color(255, 255, 255),      # White for HTTP methods (like Burp)
            'url': Color(100, 200, 255),         # Light blue for URLs
            'status': Color(255, 100, 100),      # Light red for status codes
            'header_name': Color(200, 200, 200), # Light gray for header names
            'header_value': Color(160, 160, 160), # Medium gray for header values
            'json_key': Color(255, 165, 0),      # Orange/yellow for JSON keys (like Burp)
            'json_string': Color(100, 255, 100), # Bright green for JSON strings (like Burp)
            'json_number': Color(100, 200, 255), # Light blue/cyan for JSON numbers (like Burp)
            'json_boolean': Color(100, 200, 255), # Light blue/cyan for JSON booleans (like Burp)
            'json_null': Color(150, 150, 150),   # Gray for JSON null
            'xml_tag': Color(100, 200, 255),     # Light blue for XML tags
            'xml_attr': Color(255, 165, 0),      # Orange for XML attributes
            'comment': Color(120, 170, 120),     # Light green for comments
            'error': Color(255, 100, 100),       # Light red for errors
            'success': Color(100, 255, 100),     # Bright green for success status
            'warning': Color(255, 200, 100),     # Light orange for warning status
        }
        
        # Dark theme (more vibrant colors)
        self.dark_theme = {
            'method': Color(100, 149, 237),      # Cornflower blue for HTTP methods
            'url': Color(50, 205, 50),           # Lime green for URLs
            'status': Color(255, 69, 0),         # Orange red for status codes
            'header_name': Color(138, 43, 226),  # Blue violet for header names
            'header_value': Color(169, 169, 169), # Dark gray for header values
            'json_key': Color(255, 140, 0),      # Dark orange for JSON keys
            'json_string': Color(0, 255, 127),   # Spring green for JSON strings
            'json_number': Color(30, 144, 255),  # Dodger blue for JSON numbers
            'json_boolean': Color(255, 20, 147), # Deep pink for JSON booleans
            'json_null': Color(128, 128, 128),   # Gray for JSON null
            'xml_tag': Color(30, 144, 255),      # Dodger blue for XML tags
            'xml_attr': Color(255, 140, 0),      # Dark orange for XML attributes
            'comment': Color(144, 238, 144),     # Light green for comments
            'error': Color(220, 20, 60),         # Crimson for errors
            'success': Color(50, 205, 50),       # Lime green for success status
            'warning': Color(255, 165, 0),       # Orange for warning status
        }
    
    def _applyTheme(self):
        """Apply the current theme"""
        if self.current_theme == "burp":
            self.colors = self.burp_theme
        else:
            self.colors = self.dark_theme
            
        # Create attribute sets for different styles
        self.styles = {}
        for name, color in self.colors.items():
            attr_set = SimpleAttributeSet()
            StyleConstants.setForeground(attr_set, color)
            # Bold formatting for important elements (like Burp)
            if name in ['method', 'status', 'json_key']:
                StyleConstants.setBold(attr_set, True)
            self.styles[name] = attr_set
    
    def switch_theme(self):
        """Switch between themes"""
        self.current_theme = "dark" if self.current_theme == "burp" else "burp"
        self._applyTheme()
        return self.current_theme
    
    def highlight_http_request(self, text_pane, text):
        """Highlight HTTP request syntax"""
        if not text:
            return
            
        doc = text_pane.getStyledDocument()
        doc.remove(0, doc.getLength())
        
        lines = text.split('\n')
        pos = 0
        
        for i, line in enumerate(lines):
            if i == 0 and line.strip():
                # First line: METHOD URL HTTP/1.1
                self._highlight_request_line(doc, line, pos)
            elif ':' in line and not line.startswith(' ') and not line.startswith('\t'):
                # Header line
                self._highlight_header_line(doc, line, pos)
            elif line.strip() and self._is_json(line):
                # JSON body
                self._highlight_json_line(doc, line, pos)
            elif line.strip() and self._is_xml(line):
                # XML body
                self._highlight_xml_line(doc, line, pos)
            else:
                # Plain text
                doc.insertString(doc.getLength(), line, None)
            
            if i < len(lines) - 1:
                doc.insertString(doc.getLength(), '\n', None)
                pos += len(line) + 1
            else:
                pos += len(line)
    
    def highlight_http_response(self, text_pane, text):
        """Highlight HTTP response syntax"""
        if not text:
            return
            
        doc = text_pane.getStyledDocument()
        doc.remove(0, doc.getLength())
        
        lines = text.split('\n')
        pos = 0
        body_started = False
        json_content = ""
        
        for i, line in enumerate(lines):
            if i == 0 and line.startswith('HTTP/'):
                # Status line: HTTP/1.1 200 OK
                self._highlight_status_line(doc, line, pos)
            elif ':' in line and not body_started and not line.startswith(' '):
                # Header line
                self._highlight_header_line(doc, line, pos)
            elif not line.strip() and not body_started:
                # Empty line marks start of body
                body_started = True
                doc.insertString(doc.getLength(), line, None)
            elif body_started:
                # Body content
                json_content += line + ('\n' if i < len(lines) - 1 else '')
            else:
                # Plain text
                doc.insertString(doc.getLength(), line, None)
            
            if i < len(lines) - 1:
                doc.insertString(doc.getLength(), '\n', None)
                pos += len(line) + 1
            else:
                pos += len(line)
        
        # Highlight JSON/XML body content
        if json_content.strip():
            if self._is_json(json_content):
                self._highlight_json_content(doc, json_content)
            elif self._is_xml(json_content):
                self._highlight_xml_content(doc, json_content)
    
    def _highlight_request_line(self, doc, line, pos):
        """Highlight HTTP request line (METHOD URL HTTP/1.1)"""
        parts = line.split(' ', 2)
        if len(parts) >= 2:
            # Method
            doc.insertString(doc.getLength(), parts[0], self.styles['method'])
            doc.insertString(doc.getLength(), ' ', None)
            
            # URL
            doc.insertString(doc.getLength(), parts[1], self.styles['url'])
            
            # HTTP version
            if len(parts) > 2:
                doc.insertString(doc.getLength(), ' ' + parts[2], None)
        else:
            doc.insertString(doc.getLength(), line, None)
    
    def _highlight_status_line(self, doc, line, pos):
        """Highlight HTTP status line"""
        parts = line.split(' ', 2)
        if len(parts) >= 2:
            # HTTP version
            doc.insertString(doc.getLength(), parts[0], None)
            doc.insertString(doc.getLength(), ' ', None)
            
            # Status code
            status_code = parts[1]
            status_style = self._get_status_style(status_code)
            doc.insertString(doc.getLength(), status_code, status_style)
            
            # Status message
            if len(parts) > 2:
                doc.insertString(doc.getLength(), ' ' + parts[2], status_style)
        else:
            doc.insertString(doc.getLength(), line, None)
    
    def _highlight_header_line(self, doc, line, pos):
        """Highlight HTTP header line"""
        if ':' in line:
            name, value = line.split(':', 1)
            doc.insertString(doc.getLength(), name, self.styles['header_name'])
            doc.insertString(doc.getLength(), ':', self.styles['header_name'])
            doc.insertString(doc.getLength(), value, self.styles['header_value'])
        else:
            doc.insertString(doc.getLength(), line, None)
    
    def _highlight_json_line(self, doc, line, pos):
        """Highlight a single JSON line"""
        import re
        
        # Remove existing content for this line
        remaining = line
        
        # JSON key pattern
        key_pattern = r'"([^"]+)"\s*:'
        string_pattern = r'"([^"]*)"'
        number_pattern = r'\b(\d+\.?\d*)\b'
        boolean_pattern = r'\b(true|false)\b'
        null_pattern = r'\bnull\b'
        
        while remaining:
            # Find the next token
            key_match = re.search(key_pattern, remaining)
            string_match = re.search(string_pattern, remaining)
            number_match = re.search(number_pattern, remaining)
            boolean_match = re.search(boolean_pattern, remaining)
            null_match = re.search(null_pattern, remaining)
            
            # Find the earliest match
            matches = []
            if key_match:
                matches.append((key_match.start(), 'key', key_match))
            if string_match and not (key_match and key_match.start() <= string_match.start() < key_match.end()):
                matches.append((string_match.start(), 'string', string_match))
            if number_match:
                matches.append((number_match.start(), 'number', number_match))
            if boolean_match:
                matches.append((boolean_match.start(), 'boolean', boolean_match))
            if null_match:
                matches.append((null_match.start(), 'null', null_match))
            
            if not matches:
                # No more matches, insert remaining text
                doc.insertString(doc.getLength(), remaining, None)
                break
            
            # Sort by position
            matches.sort(key=lambda x: x[0])
            pos, match_type, match = matches[0]
            
            # Insert text before match
            if pos > 0:
                doc.insertString(doc.getLength(), remaining[:pos], None)
            
            # Insert highlighted match
            if match_type == 'key':
                doc.insertString(doc.getLength(), match.group(0), self.styles['json_key'])
            elif match_type == 'string':
                doc.insertString(doc.getLength(), match.group(0), self.styles['json_string'])
            elif match_type == 'number':
                doc.insertString(doc.getLength(), match.group(0), self.styles['json_number'])
            elif match_type == 'boolean':
                doc.insertString(doc.getLength(), match.group(0), self.styles['json_boolean'])
            elif match_type == 'null':
                doc.insertString(doc.getLength(), match.group(0), self.styles['json_null'])
            
            # Update remaining text
            remaining = remaining[match.end():]
    
    def _highlight_xml_line(self, doc, line, pos):
        """Highlight XML line"""
        import re
        
        # Simple XML highlighting
        tag_pattern = r'<[^>]+>'
        
        remaining = line
        while remaining:
            match = re.search(tag_pattern, remaining)
            if not match:
                doc.insertString(doc.getLength(), remaining, None)
                break
            
            # Insert text before tag
            if match.start() > 0:
                doc.insertString(doc.getLength(), remaining[:match.start()], None)
            
            # Insert highlighted tag
            doc.insertString(doc.getLength(), match.group(0), self.styles['xml_tag'])
            
            # Update remaining
            remaining = remaining[match.end():]
    
    def _highlight_json_content(self, doc, content):
        """Highlight complete JSON content"""
        try:
            # Try to format JSON nicely first
            import json
            parsed = json.loads(content)
            formatted = json.dumps(parsed, indent=2)
            
            # Clear existing content and highlight formatted JSON
            lines = formatted.split('\n')
            for line in lines:
                self._highlight_json_line(doc, line, 0)
                doc.insertString(doc.getLength(), '\n', None)
        except:
            # If JSON parsing fails, just highlight as-is
            lines = content.split('\n')
            for line in lines:
                if line.strip():
                    self._highlight_json_line(doc, line, 0)
                else:
                    doc.insertString(doc.getLength(), line, None)
                doc.insertString(doc.getLength(), '\n', None)
    
    def _highlight_xml_content(self, doc, content):
        """Highlight complete XML content"""
        lines = content.split('\n')
        for line in lines:
            if line.strip():
                self._highlight_xml_line(doc, line, 0)
            else:
                doc.insertString(doc.getLength(), line, None)
            doc.insertString(doc.getLength(), '\n', None)
    
    def _get_status_style(self, status_code):
        """Get style for status code based on value"""
        try:
            code = int(status_code)
            if 200 <= code < 300:
                return self.styles['success']
            elif 300 <= code < 400:
                return self.styles['warning']
            elif code >= 400:
                return self.styles['error']
        except:
            pass
        return self.styles['status']
    
    def _is_json(self, text):
        """Check if text looks like JSON"""
        stripped = text.strip()
        return (stripped.startswith('{') and stripped.endswith('}')) or \
               (stripped.startswith('[') and stripped.endswith(']')) or \
               ('{"' in stripped or '[{' in stripped)
    
    def _is_xml(self, text):
        """Check if text looks like XML"""
        stripped = text.strip()
        return stripped.startswith('<') and '>' in stripped
    
    def highlight_json(self, text_pane, text):
        """Highlight JSON content only"""
        if not text:
            return
            
        doc = text_pane.getStyledDocument()
        doc.remove(0, doc.getLength())
        
        try:
            # Try to format JSON nicely first
            import json
            parsed = json.loads(text)
            formatted = json.dumps(parsed, indent=2)
            
            # Highlight formatted JSON
            lines = formatted.split('\n')
            for line in lines:
                if line.strip():
                    self._highlight_json_line(doc, line, 0)
                else:
                    doc.insertString(doc.getLength(), line, None)
                doc.insertString(doc.getLength(), '\n', None)
        except:
            # If JSON parsing fails, just highlight as-is
            lines = text.split('\n')
            for line in lines:
                if line.strip():
                    self._highlight_json_line(doc, line, 0)
                else:
                    doc.insertString(doc.getLength(), line, None)
                doc.insertString(doc.getLength(), '\n', None)
    
    def highlight_xml(self, text_pane, text):
        """Highlight XML content only"""
        if not text:
            return
            
        doc = text_pane.getStyledDocument()
        doc.remove(0, doc.getLength())
        
        lines = text.split('\n')
        for line in lines:
            if line.strip():
                self._highlight_xml_line(doc, line, 0)
            else:
                doc.insertString(doc.getLength(), line, None)
            doc.insertString(doc.getLength(), '\n', None)
    
    def highlight_form_data(self, text_pane, text):
        """Highlight form data content only"""
        if not text:
            return
            
        doc = text_pane.getStyledDocument()
        doc.remove(0, doc.getLength())
        
        # Simple form data highlighting
        doc.insertString(doc.getLength(), text, None)

# Try to import additional libraries
try:
    import xml.etree.ElementTree as ET
except:
    ET = None

class BurpExtender(IBurpExtender, ITab, IHttpListener, IMessageEditorController, IContextMenuFactory):
    
    def registerExtenderCallbacks(self, callbacks):
        """Initialize the extension"""
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        # Set extension name
        callbacks.setExtensionName("Swagger API Tester")
        
        # Initialize variables
        self.swagger_spec = None
        self.endpoints = []
        self.current_endpoint = None
        self.auth_headers = {}  # Authentication headers
        self.custom_headers = {}  # Deprecated - use global headers table instead
        self.base_url = ""

        
        # Initialize syntax highlighter
        self.syntax_highlighter = SyntaxHighlighter()
        self._updating_request_text = False
        self._current_theme = "burp"
        
        # Create GUI
        self._createUI()
        
        # Register as tab
        callbacks.addSuiteTab(self)
        
        # Register HTTP listener
        callbacks.registerHttpListener(self)
        
        # Register context menu factory
        callbacks.registerContextMenuFactory(self)
        
        # Print output
        callbacks.printOutput("Swagger API Tester extension loaded successfully!")
        callbacks.printOutput("Based on autoswagger project")
        
    def _createUI(self):
        """Create the main UI"""
        self._mainPanel = JPanel(BorderLayout())
        
        # Create main tabbed pane
        self._tabbedPane = JTabbedPane()
        
        # Tab 1: Swagger Import
        self._importTab = self._createImportTab()
        self._tabbedPane.addTab("Import Swagger", self._importTab)
        
        # Tab 2: API Tester
        self._testerTab = self._createTesterTab()
        self._tabbedPane.addTab("API Tester", self._testerTab)
        
        # Tab 3: Settings
        self._settingsTab = self._createSettingsTab()
        self._tabbedPane.addTab("Settings", self._settingsTab)
        

        
        self._mainPanel.add(self._tabbedPane, BorderLayout.CENTER)
        
    def _createImportTab(self):
        """Create the Swagger import tab"""
        panel = JPanel(BorderLayout())
        
        # Top panel for URL/File input
        topPanel = JPanel()
        layout = GroupLayout(topPanel)
        topPanel.setLayout(layout)
        layout.setAutoCreateGaps(True)
        layout.setAutoCreateContainerGaps(True)
        
        # Components
        urlLabel = JLabel("Swagger URL:")
        self._urlField = JTextField(50)
        self._urlField.setToolTipText("Enter Swagger JSON/YAML URL (e.g., https://api.example.com/swagger.json)")
        
        fetchButton = JButton("Fetch from URL", actionPerformed=self._fetchFromURL)
        fileButton = JButton("Load from File", actionPerformed=self._loadFromFile)
        
        # Example URL patterns
        exampleLabel = JLabel("Example formats:")
        exampleText = JTextArea(3, 50)
        exampleText.setText("https://api.example.com/swagger.json\n" +
                           "https://api.example.com/swagger/?action=get&name=test\n" +
                           "https://api.example.com/v2/swagger.yaml")
        exampleText.setEditable(False)
        exampleText.setBackground(panel.getBackground())
        
        # Progress bar
        self._progressBar = JProgressBar()
        self._progressBar.setStringPainted(True)
        self._progressBar.setString("Ready")
        
        # Layout
        layout.setHorizontalGroup(
            layout.createParallelGroup()
                .addGroup(layout.createSequentialGroup()
                    .addComponent(urlLabel)
                    .addComponent(self._urlField))
                .addGroup(layout.createSequentialGroup()
                    .addComponent(fetchButton)
                    .addComponent(fileButton))
                .addComponent(exampleLabel)
                .addComponent(exampleText)
                .addComponent(self._progressBar)
        )
        
        layout.setVerticalGroup(
            layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(urlLabel)
                    .addComponent(self._urlField))
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(fetchButton)
                    .addComponent(fileButton))
                .addComponent(exampleLabel)
                .addComponent(exampleText)
                .addComponent(self._progressBar)
        )
        
        # Center panel for parsed endpoints
        centerPanel = JPanel(BorderLayout())
        centerPanel.setBorder(BorderFactory.createTitledBorder("Parsed Endpoints"))
        
        # Endpoints table
        self._endpointsTableModel = DefaultTableModel(["Method", "Path", "Description"], 0)
        self._endpointsTable = JTable(self._endpointsTableModel)
        scrollPane = JScrollPane(self._endpointsTable)
        centerPanel.add(scrollPane, BorderLayout.CENTER)
        
        # Bottom panel for spec info and base URL
        bottomPanel = JPanel(BorderLayout())
        bottomPanel.setBorder(BorderFactory.createTitledBorder("Specification Info"))
        
        # Base URL panel
        baseUrlPanel = JPanel()
        baseUrlLayout = GroupLayout(baseUrlPanel)
        baseUrlPanel.setLayout(baseUrlLayout)
        baseUrlLayout.setAutoCreateGaps(True)
        baseUrlLayout.setAutoCreateContainerGaps(True)
        
        baseUrlLabel = JLabel("Base URL:")
        self._baseUrlField = JTextField(40)
        self._baseUrlField.setToolTipText("Edit the base URL for API requests")
        updateBaseUrlButton = JButton("Update Base URL", actionPerformed=self._updateBaseUrl)
        
        baseUrlLayout.setHorizontalGroup(
            baseUrlLayout.createSequentialGroup()
                .addComponent(baseUrlLabel)
                .addComponent(self._baseUrlField)
                .addComponent(updateBaseUrlButton)
        )
        
        baseUrlLayout.setVerticalGroup(
            baseUrlLayout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                .addComponent(baseUrlLabel)
                .addComponent(self._baseUrlField)
                .addComponent(updateBaseUrlButton)
        )
        
        # Spec info area
        self._specInfoArea = JTextArea(5, 50)
        self._specInfoArea.setEditable(False)
        
        # Add components to bottom panel
        bottomPanel.add(baseUrlPanel, BorderLayout.NORTH)
        bottomPanel.add(JScrollPane(self._specInfoArea), BorderLayout.CENTER)
        
        # Add all panels
        panel.add(topPanel, BorderLayout.NORTH)
        panel.add(centerPanel, BorderLayout.CENTER)
        panel.add(bottomPanel, BorderLayout.SOUTH)
        
        return panel
        
    def _createTesterTab(self):
        """Create the API testing tab"""
        panel = JPanel(BorderLayout())
        
        # Left panel - Endpoint selector
        leftPanel = JPanel(BorderLayout())
        leftPanel.setBorder(BorderFactory.createTitledBorder("Endpoints"))
        leftPanel.setPreferredSize(Dimension(300, 600))
        
        # Apply dark theme to the panel
        leftPanel.setBackground(Color(35, 35, 35))  # Dark background
        leftPanel.setForeground(Color(200, 200, 200))  # Light text
        
        # Endpoint list
        self._endpointListModel = DefaultListModel()
        self._endpointList = JList(self._endpointListModel)
        self._endpointList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self._endpointList.addListSelectionListener(lambda e: self._selectEndpoint())
        
        # Make the list more visible with better styling - Dark theme
        self._endpointList.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._endpointList.setBackground(Color(45, 45, 45))  # Dark gray background
        self._endpointList.setForeground(Color(200, 200, 200))  # Light gray text
        self._endpointList.setSelectionBackground(Color(100, 200, 255))  # Blue selection
        self._endpointList.setSelectionForeground(Color.WHITE)  # White selection text
        self._endpointList.setToolTipText("Click on an endpoint to load it for testing")
        
        # Add a visible border to the list - Dark theme
        self._endpointList.setBorder(BorderFactory.createLineBorder(Color(100, 100, 100)))
        
        # Set minimum size to ensure visibility
        self._endpointList.setMinimumSize(Dimension(250, 400))
        
        # Add a label above the list
        listLabel = JLabel("Available Endpoints:")
        listLabel.setFont(Font("Dialog", Font.BOLD, 14))
        listLabel.setForeground(Color(200, 200, 200))  # Light text for dark theme
        listLabel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5))
        
        # Add endpoint count label and refresh button in a small panel
        infoPanel = JPanel(BorderLayout())
        infoPanel.setBackground(Color(35, 35, 35))  # Dark background
        
        self._endpointCountLabel = JLabel("No endpoints loaded")
        self._endpointCountLabel.setFont(Font("Dialog", Font.PLAIN, 11))
        self._endpointCountLabel.setForeground(Color(150, 150, 150))  # Medium gray for dark theme
        self._endpointCountLabel.setBorder(BorderFactory.createEmptyBorder(0, 5, 5, 5))
        
        refreshButton = JButton("Refresh List", actionPerformed=self._refreshEndpointList)
        refreshButton.setToolTipText("Refresh the endpoint list")
        refreshButton.setBackground(Color(60, 60, 60))  # Dark button background
        refreshButton.setForeground(Color(200, 200, 200))  # Light button text
        
        infoPanel.add(self._endpointCountLabel, BorderLayout.WEST)
        infoPanel.add(refreshButton, BorderLayout.EAST)
        
        leftPanel.add(listLabel, BorderLayout.NORTH)
        leftPanel.add(infoPanel, BorderLayout.NORTH)
        leftPanel.add(JScrollPane(self._endpointList), BorderLayout.CENTER)
        
        # Add a debug button to manually populate the list
        debugButton = JButton("Debug List", actionPerformed=self._debugEndpointList)
        debugButton.setToolTipText("Debug endpoint list contents")
        debugButton.setBackground(Color(60, 60, 60))  # Dark button background
        debugButton.setForeground(Color(200, 200, 200))  # Light button text
        infoPanel.add(debugButton, BorderLayout.CENTER)
        
        # Right panel - Request/Response editor
        rightPanel = JPanel(BorderLayout())
        
        # Create tabbed pane for request details
        requestTabbedPane = JTabbedPane()
        
        # Request editor panel
        requestPanel = JPanel(BorderLayout())
        requestPanel.setBorder(BorderFactory.createTitledBorder("Request"))
        
        # Request controls
        controlPanel = JPanel()
        controlLayout = GroupLayout(controlPanel)
        controlPanel.setLayout(controlLayout)
        controlLayout.setAutoCreateGaps(True)
        controlLayout.setAutoCreateContainerGaps(True)
        
        # Method and URL
        methodLabel = JLabel("Method:")
        self._methodCombo = JComboBox(["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
        
        urlLabel = JLabel("URL:")
        self._requestUrlField = JTextField(40)
        
        # Send button
        self._sendButton = JButton("Send Request", actionPerformed=self._sendRequest)
        self._sendButton.setBackground(Color(216, 102, 51))
        
        # Quick base URL change
        quickBaseUrlLabel = JLabel("Base URL:")
        self._quickBaseUrlCombo = JComboBox()
        self._quickBaseUrlCombo.setEditable(True)
        self._quickBaseUrlCombo.setToolTipText("Select or enter a base URL")
        self._quickBaseUrlCombo.addActionListener(lambda e: self._quickChangeBaseUrl())
        
        # Content type
        contentTypeLabel = JLabel("Content-Type:")
        self._contentTypeCombo = JComboBox([
            "application/json",
            "application/xml", 
            "application/x-www-form-urlencoded",
            "multipart/form-data",
            "text/plain"
        ])
        
        # Layout controls
        controlLayout.setHorizontalGroup(
            controlLayout.createParallelGroup()
                .addGroup(controlLayout.createSequentialGroup()
                    .addComponent(methodLabel)
                    .addComponent(self._methodCombo, 100, 100, 100)
                    .addComponent(urlLabel)
                    .addComponent(self._requestUrlField))
                .addGroup(controlLayout.createSequentialGroup()
                    .addComponent(quickBaseUrlLabel)
                    .addComponent(self._quickBaseUrlCombo, 300, 300, 500))
                .addGroup(controlLayout.createSequentialGroup()
                    .addComponent(contentTypeLabel)
                    .addComponent(self._contentTypeCombo, 200, 200, 200)
                    .addComponent(self._sendButton))
        )
        
        controlLayout.setVerticalGroup(
            controlLayout.createSequentialGroup()
                .addGroup(controlLayout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(methodLabel)
                    .addComponent(self._methodCombo)
                    .addComponent(urlLabel)
                    .addComponent(self._requestUrlField))
                .addGroup(controlLayout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(quickBaseUrlLabel)
                    .addComponent(self._quickBaseUrlCombo))
                .addGroup(controlLayout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(contentTypeLabel)
                    .addComponent(self._contentTypeCombo)
                    .addComponent(self._sendButton))
        )
        
        requestPanel.add(controlPanel, BorderLayout.NORTH)
        
        # Request body editor with syntax highlighting
        self._requestEditor = JTextPane()
        self._requestEditor.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._requestEditor.setDocument(DefaultStyledDocument())
        self._requestEditor.setPreferredSize(Dimension(500, 250))
        
        # Add popup menu to request editor
        self._createRequestPopupMenu()
        self._requestEditor.addMouseListener(RequestMouseListener(self))
        
        # Add document listener for live syntax highlighting (disabled by default to prevent duplication)
        # self._requestEditor.getDocument().addDocumentListener(RequestDocumentListener(self))
        
        # Create request editor panel with buttons
        requestEditorPanel = JPanel(BorderLayout())
        requestEditorPanel.add(JScrollPane(self._requestEditor), BorderLayout.CENTER)
        
        # Add formatting buttons
        formatButtonPanel = JPanel()
        prettyPrintButton = JButton("Pretty Print", actionPerformed=self._prettyPrintRequest)
        prettyPrintButton.setToolTipText("Format JSON/XML in request body")
        formatButtonPanel.add(prettyPrintButton)
        
        minifyButton = JButton("Minify", actionPerformed=self._minifyRequest)
        minifyButton.setToolTipText("Compress JSON/XML in request body")
        formatButtonPanel.add(minifyButton)
        
        highlightButton = JButton("Highlight", actionPerformed=self._highlightRequest)
        highlightButton.setToolTipText("Apply syntax highlighting to request")
        formatButtonPanel.add(highlightButton)
        
        themeButton = JButton("Burp Theme", actionPerformed=self._toggleTheme)
        themeButton.setToolTipText("Toggle between Burp and Dark color themes")
        formatButtonPanel.add(themeButton)
        self._themeButton = themeButton
        
        requestEditorPanel.add(formatButtonPanel, BorderLayout.SOUTH)
        requestPanel.add(requestEditorPanel, BorderLayout.CENTER)
        
        # Parameters panel
        parametersPanel = self._createParametersPanel()
        
        # Headers panel for this request
        requestHeadersPanel = self._createRequestHeadersPanel()
        
        # Add tabs to request tabbed pane
        requestTabbedPane.addTab("Request", requestPanel)
        requestTabbedPane.addTab("Parameters", parametersPanel)
        requestTabbedPane.addTab("Headers", requestHeadersPanel)
        
        # Response panel
        responsePanel = JPanel(BorderLayout())
        responsePanel.setBorder(BorderFactory.createTitledBorder("Response"))
        
        # Response info
        self._responseInfoLabel = JLabel("No response yet")
        responsePanel.add(self._responseInfoLabel, BorderLayout.NORTH)
        
        # Response body viewer with syntax highlighting
        self._responseViewer = JTextPane()
        self._responseViewer.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._responseViewer.setDocument(DefaultStyledDocument())
        self._responseViewer.setEditable(False)
        self._responseViewer.setPreferredSize(Dimension(500, 250))
        responsePanel.add(JScrollPane(self._responseViewer), BorderLayout.CENTER)
        
        # Split pane for request/response
        splitPane = JSplitPane(JSplitPane.VERTICAL_SPLIT, requestTabbedPane, responsePanel)
        splitPane.setDividerLocation(400)
        rightPanel.add(splitPane, BorderLayout.CENTER)
        
        # Main split pane
        mainSplitPane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, leftPanel, rightPanel)
        mainSplitPane.setDividerLocation(300)
        panel.add(mainSplitPane, BorderLayout.CENTER)
        
        return panel
        
    def _createSettingsTab(self):
        """Create the settings tab"""
        panel = JPanel()
        layout = GroupLayout(panel)
        panel.setLayout(layout)
        layout.setAutoCreateGaps(True)
        layout.setAutoCreateContainerGaps(True)
        
        # Authentication section
        authBorder = BorderFactory.createTitledBorder("Authentication")
        authPanel = JPanel()
        authPanel.setBorder(authBorder)
        authLayout = GroupLayout(authPanel)
        authPanel.setLayout(authLayout)
        authLayout.setAutoCreateGaps(True)
        authLayout.setAutoCreateContainerGaps(True)
        
        # Auth type
        authTypeLabel = JLabel("Auth Type:")
        self._authTypeCombo = JComboBox(["None", "Bearer Token", "API Key", "Basic Auth", "Custom Header"])
        self._authTypeCombo.addActionListener(lambda e: self._updateAuthFields())
        
        # Auth fields
        self._authKeyLabel = JLabel("Key:")
        self._authKeyField = JTextField(20)
        self._authValueLabel = JLabel("Value:")
        self._authValueField = JTextField(30)
        
        # Apply auth button
        applyAuthButton = JButton("Apply Authentication", actionPerformed=self._applyAuth)
        
        # Layout auth panel
        authLayout.setHorizontalGroup(
            authLayout.createParallelGroup()
                .addGroup(authLayout.createSequentialGroup()
                    .addComponent(authTypeLabel)
                    .addComponent(self._authTypeCombo))
                .addGroup(authLayout.createSequentialGroup()
                    .addComponent(self._authKeyLabel)
                    .addComponent(self._authKeyField)
                    .addComponent(self._authValueLabel)
                    .addComponent(self._authValueField))
                .addComponent(applyAuthButton)
        )
        
        authLayout.setVerticalGroup(
            authLayout.createSequentialGroup()
                .addGroup(authLayout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(authTypeLabel)
                    .addComponent(self._authTypeCombo))
                .addGroup(authLayout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(self._authKeyLabel)
                    .addComponent(self._authKeyField)
                    .addComponent(self._authValueLabel)
                    .addComponent(self._authValueField))
                .addComponent(applyAuthButton)
        )
        
        # Custom headers section
        headersBorder = BorderFactory.createTitledBorder("Custom Headers")
        headersPanel = JPanel(BorderLayout())
        headersPanel.setBorder(headersBorder)
        
        # Headers table
        self._headersTableModel = DefaultTableModel(["Header Name", "Header Value"], 0)
        self._headersTable = JTable(self._headersTableModel)
        headersPanel.add(JScrollPane(self._headersTable), BorderLayout.CENTER)
        
        # Headers buttons
        headerButtonPanel = JPanel()
        addHeaderButton = JButton("Add Header", actionPerformed=self._addHeader)
        removeHeaderButton = JButton("Remove Selected", actionPerformed=self._removeHeader)
        headerButtonPanel.add(addHeaderButton)
        headerButtonPanel.add(removeHeaderButton)
        headersPanel.add(headerButtonPanel, BorderLayout.SOUTH)
        
        # Request options
        optionsBorder = BorderFactory.createTitledBorder("Request Options")
        optionsPanel = JPanel()
        optionsPanel.setBorder(optionsBorder)
        optionsLayout = GroupLayout(optionsPanel)
        optionsPanel.setLayout(optionsLayout)
        optionsLayout.setAutoCreateGaps(True)
        optionsLayout.setAutoCreateContainerGaps(True)
        
        # Options checkboxes
        self._followRedirectsCheck = JCheckBox("Follow Redirects", True)
        self._validateCertCheck = JCheckBox("Validate SSL Certificates", False)
        self._includeDefaultHeadersCheck = JCheckBox("Include Default Headers", True)
        
        # Timeout
        timeoutLabel = JLabel("Timeout (seconds):")
        self._timeoutField = JTextField("30", 5)
        
        # Layout options
        optionsLayout.setHorizontalGroup(
            optionsLayout.createParallelGroup()
                .addComponent(self._followRedirectsCheck)
                .addComponent(self._validateCertCheck)
                .addComponent(self._includeDefaultHeadersCheck)
                .addGroup(optionsLayout.createSequentialGroup()
                    .addComponent(timeoutLabel)
                    .addComponent(self._timeoutField))
        )
        
        optionsLayout.setVerticalGroup(
            optionsLayout.createSequentialGroup()
                .addComponent(self._followRedirectsCheck)
                .addComponent(self._validateCertCheck)
                .addComponent(self._includeDefaultHeadersCheck)
                .addGroup(optionsLayout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(timeoutLabel)
                    .addComponent(self._timeoutField))
        )
        
        # Main layout
        layout.setHorizontalGroup(
            layout.createParallelGroup()
                .addComponent(authPanel)
                .addComponent(headersPanel)
                .addComponent(optionsPanel)
        )
        
        layout.setVerticalGroup(
            layout.createSequentialGroup()
                .addComponent(authPanel)
                .addComponent(headersPanel)
                .addComponent(optionsPanel)
        )
        
        return JScrollPane(panel)
    
    def _createParametersPanel(self):
        """Create the parameters panel with tables for different parameter types"""
        panel = JPanel(BorderLayout())
        
        # Create tabbed pane for different parameter types
        paramTabbedPane = JTabbedPane()
        
        # Path parameters table
        self._pathParamsTableModel = DefaultTableModel(["Name", "Value", "Type", "Required", "Description"], 0)
        self._pathParamsTable = JTable(self._pathParamsTableModel)
        pathScrollPane = JScrollPane(self._pathParamsTable)
        paramTabbedPane.addTab("Path", pathScrollPane)
        
        # Query parameters table
        self._queryParamsTableModel = DefaultTableModel(["Name", "Value", "Type", "Required", "Description"], 0)
        self._queryParamsTable = JTable(self._queryParamsTableModel)
        queryScrollPane = JScrollPane(self._queryParamsTable)
        
        # Query parameters control panel
        queryControlPanel = JPanel(BorderLayout())
        queryButtonPanel = JPanel()
        addQueryButton = JButton("Add Parameter", actionPerformed=self._addQueryParam)
        removeQueryButton = JButton("Remove Selected", actionPerformed=self._removeQueryParam)
        queryButtonPanel.add(addQueryButton)
        queryButtonPanel.add(removeQueryButton)
        queryControlPanel.add(queryScrollPane, BorderLayout.CENTER)
        queryControlPanel.add(queryButtonPanel, BorderLayout.SOUTH)
        paramTabbedPane.addTab("Query", queryControlPanel)
        
        # Header parameters table
        self._headerParamsTableModel = DefaultTableModel(["Name", "Value", "Type", "Required", "Description"], 0)
        self._headerParamsTable = JTable(self._headerParamsTableModel)
        headerScrollPane = JScrollPane(self._headerParamsTable)
        paramTabbedPane.addTab("Headers", headerScrollPane)
        
        panel.add(paramTabbedPane, BorderLayout.CENTER)
        
        # Update button
        updateParamsButton = JButton("Update Request", actionPerformed=self._updateRequestFromParams)
        panel.add(updateParamsButton, BorderLayout.SOUTH)
        
        return panel
    
    def _createRequestHeadersPanel(self):
        """Create panel for request-specific headers"""
        panel = JPanel(BorderLayout())
        
        # Headers table for this specific request
        self._requestHeadersTableModel = DefaultTableModel(["Header Name", "Header Value", "Source"], 0)
        self._requestHeadersTable = JTable(self._requestHeadersTableModel)
        
        # Make the source column non-editable
        self._requestHeadersTable.getColumnModel().getColumn(2).setCellEditor(None)
        
        scrollPane = JScrollPane(self._requestHeadersTable)
        panel.add(scrollPane, BorderLayout.CENTER)
        
        # Control panel
        controlPanel = JPanel()
        addHeaderBtn = JButton("Add Header", actionPerformed=self._addRequestHeader)
        removeHeaderBtn = JButton("Remove Selected", actionPerformed=self._removeRequestHeader)
        refreshHeadersBtn = JButton("Refresh from Spec", actionPerformed=self._refreshHeadersFromSpec)
        
        controlPanel.add(addHeaderBtn)
        controlPanel.add(removeHeaderBtn)
        controlPanel.add(refreshHeadersBtn)
        panel.add(controlPanel, BorderLayout.SOUTH)
        
        return panel
        

    
    def _fetchFromURL(self, event):
        """Fetch Swagger spec from URL"""
        url = self._urlField.getText().strip()
        if not url:
            JOptionPane.showMessageDialog(self._mainPanel, 
                "Please enter a valid URL", "Error", JOptionPane.ERROR_MESSAGE)
            return
            
        # Run in separate thread
        Thread(target=self._fetchSwaggerSpec, args=(url,)).start()
        
    def _fetchSwaggerSpec(self, url):
        """Fetch and parse Swagger specification"""
        try:
            self._progressBar.setString("Fetching specification...")
            self._progressBar.setIndeterminate(True)
            
            # Parse the URL
            parsed_url = urlparse(url)
            
            # Check if URL contains query parameters
            if parsed_url.query:
                # This might be a dynamic swagger endpoint
                self._callbacks.printOutput("Fetching swagger from: " + url)
            
            # Create connection
            connection = URL(url).openConnection()
            connection.setRequestProperty("User-Agent", "Swagger-API-Tester/1.0")
            connection.setRequestProperty("Accept", "application/json, application/yaml, text/yaml, */*")
            connection.setConnectTimeout(10000)
            connection.setReadTimeout(10000)
            
            # Read response
            reader = BufferedReader(InputStreamReader(connection.getInputStream()))
            response = ""
            line = reader.readLine()
            while line is not None:
                response += line + "\n"
                line = reader.readLine()
            reader.close()
            
            # Parse specification
            self._parseSwaggerSpec(response, url)
            
        except Exception as e:
            self._progressBar.setIndeterminate(False)
            self._progressBar.setString("Error: " + str(e))
            self._callbacks.printError("Error fetching swagger spec: " + str(e))
            JOptionPane.showMessageDialog(self._mainPanel,
                "Error fetching specification: " + str(e), 
                "Error", JOptionPane.ERROR_MESSAGE)
            
    def _parseSwaggerSpec(self, content, source_url):
        """Parse Swagger/OpenAPI specification"""
        try:
            # Try parsing as JSON first
            try:
                self.swagger_spec = json.loads(content)
            except:
                # Try parsing as YAML
                if yaml:
                    try:
                        self.swagger_spec = yaml.safe_load(content)
                    except Exception as e:
                        raise Exception("Failed to parse as JSON or YAML: " + str(e))
                else:
                    raise Exception("Failed to parse as JSON and YAML support is not available")
            
            # Extract base URL
            self.base_url = self._extractBaseUrl(source_url)
            
            # Update spec info
            self._updateSpecInfo()
            
            # Parse endpoints
            self._parseEndpoints()
            
            self._progressBar.setIndeterminate(False)
            self._progressBar.setString("Successfully loaded " + str(len(self.endpoints)) + " endpoints")
            
        except Exception as e:
            self._progressBar.setIndeterminate(False)
            self._progressBar.setString("Parse error: " + str(e))
            self._callbacks.printError("Error parsing swagger spec: " + str(e))
            JOptionPane.showMessageDialog(self._mainPanel,
                "Error parsing specification: " + str(e), 
                "Error", JOptionPane.ERROR_MESSAGE)
            
    def _extractBaseUrl(self, source_url):
        """Extract base URL from source URL and swagger spec"""
        parsed = urlparse(source_url)
        base = parsed.scheme + "://" + parsed.netloc
        
        # Check for servers in OpenAPI 3.0
        if self.swagger_spec and "servers" in self.swagger_spec:
            servers = self.swagger_spec["servers"]
            if servers and len(servers) > 0:
                server_url = servers[0].get("url", "")
                if server_url.startswith("http"):
                    return server_url
                elif server_url.startswith("/"):
                    return base + server_url
                    
        # Check for host/basePath in Swagger 2.0
        if self.swagger_spec:
            host = self.swagger_spec.get("host", "")
            base_path = self.swagger_spec.get("basePath", "")
            schemes = self.swagger_spec.get("schemes", ["https"])
            
            if host:
                scheme = schemes[0] if schemes else "https"
                return scheme + "://" + host + base_path
                
        return base
        
    def _updateSpecInfo(self):
        """Update specification info display"""
        if not self.swagger_spec:
            return
            
        info = []
        
        # Title and version
        if "info" in self.swagger_spec:
            spec_info = self.swagger_spec["info"]
            info.append("Title: " + spec_info.get("title", "N/A"))
            info.append("Version: " + spec_info.get("version", "N/A"))
            if "description" in spec_info:
                info.append("Description: " + spec_info["description"][:200] + "...")
                
        # OpenAPI/Swagger version
        if "openapi" in self.swagger_spec:
            info.append("OpenAPI Version: " + self.swagger_spec["openapi"])
        elif "swagger" in self.swagger_spec:
            info.append("Swagger Version: " + self.swagger_spec["swagger"])
            
        # Base URL
        info.append("Base URL: " + self.base_url)
        # Update the base URL field
        self._baseUrlField.setText(self.base_url)
        
        # Populate quick base URL combo with common patterns
        self._quickBaseUrlCombo.removeAllItems()
        self._quickBaseUrlCombo.addItem(self.base_url)
        
        # Add common environment variations
        parsed = urlparse(self.base_url)
        base_host = parsed.netloc
        
        # Common environment patterns
        environments = ["dev", "staging", "test", "qa", "prod", "production"]
        for env in environments:
            # Try subdomain pattern: env.example.com
            if not base_host.startswith(env + "."):
                env_url = parsed.scheme + "://" + env + "." + base_host + parsed.path
                self._quickBaseUrlCombo.addItem(env_url)
            
            # Try path pattern: example.com/env
            if parsed.path and not parsed.path.endswith("/" + env):
                env_url = parsed.scheme + "://" + base_host + "/" + env + parsed.path
                self._quickBaseUrlCombo.addItem(env_url)
        
        # Add localhost variations
        if "localhost" not in base_host and "127.0.0.1" not in base_host:
            self._quickBaseUrlCombo.addItem("http://localhost:8080" + parsed.path)
            self._quickBaseUrlCombo.addItem("http://localhost:3000" + parsed.path)
        
        # Security schemes
        if "components" in self.swagger_spec and "securitySchemes" in self.swagger_spec["components"]:
            schemes = self.swagger_spec["components"]["securitySchemes"].keys()
            info.append("Security Schemes: " + ", ".join(schemes))
        elif "securityDefinitions" in self.swagger_spec:
            schemes = self.swagger_spec["securityDefinitions"].keys()
            info.append("Security Schemes: " + ", ".join(schemes))
            
        self._specInfoArea.setText("\n".join(info))
        
    def _parseEndpoints(self):
        """Parse endpoints from swagger spec"""
        self.endpoints = []
        self._endpointsTableModel.setRowCount(0)
        self._endpointListModel.clear()
        
        if not self.swagger_spec or "paths" not in self.swagger_spec:
            return
            
        paths = self.swagger_spec["paths"]
        
        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue
                
            for method, details in methods.items():
                if method.upper() not in ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]:
                    continue
                    
                endpoint = {
                    "path": path,
                    "method": method.upper(),
                    "details": details,
                    "description": details.get("summary", details.get("description", ""))
                }
                
                self.endpoints.append(endpoint)
                
                # Add to table
                self._endpointsTableModel.addRow([
                    endpoint["method"],
                    endpoint["path"],
                    endpoint["description"][:100]
                ])
                
                # Add to list
                endpoint_text = endpoint["method"] + " " + endpoint["path"]
                self._endpointListModel.addElement(endpoint_text)
                # Debug output
                self._callbacks.printOutput("Added endpoint to list: " + endpoint_text)
        
        # Update endpoint count label
        if hasattr(self, '_endpointCountLabel'):
            count = len(self.endpoints)
            if count == 0:
                self._endpointCountLabel.setText("No endpoints found")
            elif count == 1:
                self._endpointCountLabel.setText("1 endpoint loaded")
            else:
                self._endpointCountLabel.setText(str(count) + " endpoints loaded")
    
    def _refreshEndpointList(self, event):
        """Refresh the endpoint list display"""
        try:
            if self.swagger_spec:
                self._parseEndpoints()
                
                # Force the list to repaint and show contents
                self._endpointList.revalidate()
                self._endpointList.repaint()
                
                # Show debug info
                list_size = self._endpointListModel.getSize()
                self._callbacks.printOutput("Endpoint list refreshed. List size: " + str(list_size))
                
                JOptionPane.showMessageDialog(self._mainPanel,
                    "Endpoint list refreshed successfully. " + str(list_size) + " endpoints loaded.",
                    "Success", JOptionPane.INFORMATION_MESSAGE)
            else:
                JOptionPane.showMessageDialog(self._mainPanel,
                    "No Swagger specification loaded",
                    "Error", JOptionPane.ERROR_MESSAGE)
        except Exception as e:
                            JOptionPane.showMessageDialog(self._mainPanel,
                    "Error refreshing endpoint list: " + str(e),
                    "Error", JOptionPane.ERROR_MESSAGE)
    
    def _debugEndpointList(self, event):
        """Debug endpoint list contents"""
        try:
            list_size = self._endpointListModel.getSize()
            endpoints_count = len(self.endpoints)
            
            debug_info = "Debug Info:\n"
            debug_info += "List Model Size: " + str(list_size) + "\n"
            debug_info += "Endpoints Array Size: " + str(endpoints_count) + "\n"
            debug_info += "List Visible: " + str(self._endpointList.isVisible()) + "\n"
            debug_info += "List Enabled: " + str(self._endpointList.isEnabled()) + "\n"
            
            if list_size > 0:
                debug_info += "\nFirst few items:\n"
                for i in range(min(5, list_size)):
                    item = self._endpointListModel.getElementAt(i)
                    debug_info += str(i) + ": " + str(item) + "\n"
            
            self._callbacks.printOutput(debug_info)
            JOptionPane.showMessageDialog(self._mainPanel, debug_info, "Debug Info", JOptionPane.INFORMATION_MESSAGE)
            
        except Exception as e:
            JOptionPane.showMessageDialog(self._mainPanel,
                "Error in debug: " + str(e),
                "Debug Error", JOptionPane.ERROR_MESSAGE)
                
    def _loadFromFile(self, event):
        """Load Swagger spec from file"""
        chooser = JFileChooser()
        chooser.setDialogTitle("Select Swagger/OpenAPI file")
        
        if chooser.showOpenDialog(self._mainPanel) == JFileChooser.APPROVE_OPTION:
            file = chooser.getSelectedFile()
            try:
                with open(file.getAbsolutePath(), 'r') as f:
                    content = f.read()
                    
                self._parseSwaggerSpec(content, "file://" + file.getAbsolutePath())
                
            except Exception as e:
                JOptionPane.showMessageDialog(self._mainPanel,
                    "Error loading file: " + str(e), 
                    "Error", JOptionPane.ERROR_MESSAGE)
                    
    def _selectEndpoint(self):
        """Handle endpoint selection"""
        selected = self._endpointList.getSelectedIndex()
        if selected >= 0 and selected < len(self.endpoints):
            self.current_endpoint = self.endpoints[selected]
            self._loadEndpointDetails()
            
    def _loadEndpointDetails(self):
        """Load selected endpoint details into request editor"""
        if not self.current_endpoint:
            return
            
        # Set method
        self._methodCombo.setSelectedItem(self.current_endpoint["method"])
        
        # Get endpoint details
        path = self.current_endpoint["path"]
        details = self.current_endpoint["details"]
        parameters = details.get("parameters", [])
        
        # Clear parameter tables
        self._pathParamsTableModel.setRowCount(0)
        self._queryParamsTableModel.setRowCount(0)
        self._headerParamsTableModel.setRowCount(0)
        self._requestHeadersTableModel.setRowCount(0)
        
        # Parse parameters from the spec
        self._parseEndpointParameters(parameters, details)
        
        # Build initial URL
        self._updateRequestFromParams()
        
        # Set request body with syntax highlighting
        request_body = self._buildRequestBody(details)
        self._setRequestText(request_body)
        
        # Set content type
        if "requestBody" in details:
            content = details["requestBody"].get("content", {})
            if "application/json" in content:
                self._contentTypeCombo.setSelectedItem("application/json")
            elif "application/xml" in content:
                self._contentTypeCombo.setSelectedItem("application/xml")
            elif "application/x-www-form-urlencoded" in content:
                self._contentTypeCombo.setSelectedItem("application/x-www-form-urlencoded")
        
        # Load headers from spec
        self._refreshHeadersFromSpec()
    
    def _parseEndpointParameters(self, parameters, details):
        """Parse parameters from endpoint definition"""
        for param in parameters:
            name = param.get("name", "")
            param_type = param.get("type", "string")
            required = param.get("required", False)
            description = param.get("description", "")
            param_in = param.get("in", "")
            
            # Handle schema-based parameters (OpenAPI 3.0)
            if "schema" in param:
                schema = param["schema"]
                param_type = schema.get("type", "string")
                if "enum" in schema:
                    param_type += " (enum)"
                if "format" in schema:
                    param_type += " (" + schema["format"] + ")"
            
            # Generate example value
            example_value = self._generateParamExampleValue(param)
            
            # Add to appropriate table
            if param_in == "path":
                self._pathParamsTableModel.addRow([name, example_value, param_type, str(required), description])
            elif param_in == "query":
                self._queryParamsTableModel.addRow([name, example_value, param_type, str(required), description])
            elif param_in == "header":
                self._headerParamsTableModel.addRow([name, example_value, param_type, str(required), description])
        
        # Also check for additional headers in the endpoint definition
        if "responses" in details:
            for response_code, response_data in details["responses"].items():
                if "headers" in response_data:
                    for header_name, header_data in response_data["headers"].items():
                        # These are response headers, but useful to know about
                        pass
    
    def _generateParamExampleValue(self, param):
        """Generate example value for parameter"""
        # Check for explicit example
        if "example" in param:
            return str(param["example"])
        
        # Check for default value
        if "default" in param:
            return str(param["default"])
        
        # Check schema for example
        if "schema" in param:
            schema = param["schema"]
            if "example" in schema:
                return str(schema["example"])
            if "default" in schema:
                return str(schema["default"])
            if "enum" in schema and schema["enum"]:
                return str(schema["enum"][0])
            
            # Generate by type
            param_type = schema.get("type", "string")
            format_type = schema.get("format", "")
            
            if param_type == "string":
                if format_type == "date":
                    return "2024-01-01"
                elif format_type == "date-time":
                    return "2024-01-01T00:00:00Z"
                elif format_type == "email":
                    return "user@example.com"
                elif format_type == "uuid":
                    return "550e8400-e29b-41d4-a716-446655440000"
                else:
                    return param.get("name", "value")
            elif param_type == "integer":
                return "1"
            elif param_type == "number":
                return "1.0"
            elif param_type == "boolean":
                return "true"
        
        # Fallback
        param_type = param.get("type", "string")
        if param_type == "integer":
            return "1"
        elif param_type == "number":
            return "1.0"
        elif param_type == "boolean":
            return "true"
        else:
            return param.get("name", "value")
                
    def _buildRequestBody(self, details):
        """Build example request body from endpoint details"""
        if "requestBody" not in details:
            # Check for body parameters (Swagger 2.0)
            parameters = details.get("parameters", [])
            for param in parameters:
                if param.get("in") == "body" and "schema" in param:
                    return self._schemaToExample(param["schema"])
            return ""
            
        # OpenAPI 3.0 requestBody
        request_body = details["requestBody"]
        content = request_body.get("content", {})
        
        # Try JSON first
        if "application/json" in content:
            schema = content["application/json"].get("schema", {})
            return self._schemaToExample(schema)
            
        # Try XML
        if "application/xml" in content:
            schema = content["application/xml"].get("schema", {})
            return self._schemaToXmlExample(schema)
            
        # Try form data
        if "application/x-www-form-urlencoded" in content:
            schema = content["application/x-www-form-urlencoded"].get("schema", {})
            return self._schemaToFormExample(schema)
            
        return ""
        
    def _schemaToExample(self, schema):
        """Convert JSON schema to example"""
        try:
            example = self._generateExample(schema)
            return json.dumps(example, indent=2)
        except:
            return "{}"
            
    def _generateExample(self, schema):
        """Generate example from schema with enhanced type handling"""
        if "example" in schema:
            return schema["example"]
        
        # Handle references
        if "$ref" in schema and self.swagger_spec:
            # Simple reference resolution for #/definitions/ or #/components/schemas/
            ref_path = schema["$ref"]
            if ref_path.startswith("#/definitions/"):
                def_name = ref_path.split("/")[-1]
                if "definitions" in self.swagger_spec and def_name in self.swagger_spec["definitions"]:
                    return self._generateExample(self.swagger_spec["definitions"][def_name])
            elif ref_path.startswith("#/components/schemas/"):
                schema_name = ref_path.split("/")[-1]
                if "components" in self.swagger_spec and "schemas" in self.swagger_spec["components"]:
                    if schema_name in self.swagger_spec["components"]["schemas"]:
                        return self._generateExample(self.swagger_spec["components"]["schemas"][schema_name])
            
        if "type" not in schema:
            # Handle allOf, oneOf, anyOf
            if "allOf" in schema:
                merged = {}
                for sub_schema in schema["allOf"]:
                    example = self._generateExample(sub_schema)
                    if isinstance(example, dict):
                        merged.update(example)
                return merged
            elif "oneOf" in schema and schema["oneOf"]:
                return self._generateExample(schema["oneOf"][0])
            elif "anyOf" in schema and schema["anyOf"]:
                return self._generateExample(schema["anyOf"][0])
            return {}
            
        schema_type = schema["type"]
        
        if schema_type == "object":
            obj = {}
            properties = schema.get("properties", {})
            required = schema.get("required", [])
            
            # Generate examples for required properties first
            for prop_name in required:
                if prop_name in properties:
                    obj[prop_name] = self._generateExample(properties[prop_name])
            
            # Generate examples for other properties (up to a reasonable limit)
            prop_count = 0
            for prop_name, prop_schema in properties.items():
                if prop_name not in obj and prop_count < 10:  # Limit to avoid huge objects
                    obj[prop_name] = self._generateExample(prop_schema)
                    prop_count += 1
            
            return obj
            
        elif schema_type == "array":
            items = schema.get("items", {})
            min_items = schema.get("minItems", 1)
            max_items = min(schema.get("maxItems", 3), 3)  # Limit array size
            
            examples = []
            for i in range(max(min_items, 1)):
                if i < max_items:
                    examples.append(self._generateExample(items))
            return examples
            
        elif schema_type == "string":
            if "enum" in schema:
                return schema["enum"][0]
            elif "format" in schema:
                format_type = schema["format"]
                if format_type == "date":
                    return "2024-01-01"
                elif format_type == "date-time":
                    return "2024-01-01T00:00:00Z"
                elif format_type == "email":
                    return "user@example.com"
                elif format_type == "uuid":
                    return "550e8400-e29b-41d4-a716-446655440000"
                elif format_type == "password":
                    return "password123"
                elif format_type == "uri":
                    return "https://example.com"
                elif format_type == "binary":
                    return "base64encodeddata"
            
            # Handle string constraints
            min_length = schema.get("minLength", 0)
            max_length = schema.get("maxLength", 50)
            
            base_value = "example_string"
            if len(base_value) < min_length:
                base_value = base_value * ((min_length // len(base_value)) + 1)
            if len(base_value) > max_length:
                base_value = base_value[:max_length]
            
            return base_value
            
        elif schema_type == "number":
            minimum = schema.get("minimum", 0)
            maximum = schema.get("maximum", 100)
            return float(minimum + (maximum - minimum) / 2)
            
        elif schema_type == "integer":
            minimum = schema.get("minimum", 0)
            maximum = schema.get("maximum", 100)
            return int(minimum + (maximum - minimum) / 2)
            
        elif schema_type == "boolean":
            return True
            
        return None
        
    def _schemaToXmlExample(self, schema):
        """Convert schema to XML example"""
        # Simplified XML generation
        root_name = schema.get("xml", {}).get("name", "root")
        return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<" + root_name + "></" + root_name + ">"
        
    def _schemaToFormExample(self, schema):
        """Convert schema to form data example"""
        if schema.get("type") == "object":
            properties = schema.get("properties", {})
            params = []
            for prop_name, prop_schema in properties.items():
                example_value = self._generateExample(prop_schema)
                params.append(prop_name + "=" + str(example_value))
            return "&".join(params)
        return ""
        
    def _sendRequest(self, event):
        """Send the API request"""
        Thread(target=self._performRequest).start()
        
    def _performRequest(self):
        """Perform the actual HTTP request"""
        try:
            # Get request details
            method = str(self._methodCombo.getSelectedItem())
            url = self._requestUrlField.getText()
            body = self._requestEditor.getText()
            content_type = str(self._contentTypeCombo.getSelectedItem())
            
            # Build request
            request_info = self._helpers.buildHttpRequest(URL(url))
            
            # Build headers
            headers = []
            headers.append(method + " " + urlparse(url).path + " HTTP/1.1")
            headers.append("Host: " + urlparse(url).netloc)
            
            # Add content type
            if method in ["POST", "PUT", "PATCH"] and content_type:
                headers.append("Content-Type: " + content_type)
                
            # Add headers from the request headers table (includes spec, auth, global, and manual headers)
            for i in range(self._requestHeadersTableModel.getRowCount()):
                name = self._requestHeadersTableModel.getValueAt(i, 0)
                value = self._requestHeadersTableModel.getValueAt(i, 1)
                if name and value:  # Only add non-empty headers
                    headers.append(str(name) + ": " + str(value))
                
            # Add default headers if enabled
            if self._includeDefaultHeadersCheck.isSelected():
                headers.append("User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36")
                headers.append("Accept: */*")
                
            # Build full request
            if body and method in ["POST", "PUT", "PATCH"]:
                headers.append("Content-Length: " + str(len(body)))
                full_request = "\r\n".join(headers) + "\r\n\r\n" + body
            else:
                full_request = "\r\n".join(headers) + "\r\n\r\n"
                
            # Convert to bytes
            request_bytes = self._helpers.stringToBytes(full_request)
            
            # Parse URL
            parsed = urlparse(url)
            host = parsed.hostname
            port = parsed.port if parsed.port else (443 if parsed.scheme == "https" else 80)
            use_https = parsed.scheme == "https"
            
            # Send request through Burp
            start_time = time.time()
            response = self._callbacks.makeHttpRequest(
                host, port, use_https, request_bytes
            )
            elapsed_time = time.time() - start_time
            
            # Parse response
            if response:
                response_info = self._helpers.analyzeResponse(response)
                response_body = response[response_info.getBodyOffset():]
                status_code = response_info.getStatusCode()
                
                # Update response viewer with syntax highlighting
                response_text = self._helpers.bytesToString(response_body)
                self._setResponseText(response_text, status_code)
                self._responseInfoLabel.setText(
                    "Status: " + str(status_code) + 
                    " | Length: " + str(len(response_body)) + 
                    " | Time: " + str(int(elapsed_time * 1000)) + "ms"
                )
                

                
                # Color code based on status (using Burp-style colors)
                if status_code >= 200 and status_code < 300:
                    self._responseInfoLabel.setForeground(Color(100, 255, 100))  # Bright green for success
                elif status_code >= 400:
                    self._responseInfoLabel.setForeground(Color(255, 100, 100))  # Light red for errors
                else:
                    self._responseInfoLabel.setForeground(Color(255, 200, 100))  # Light orange for other
                    
            else:
                self._setResponseText("No response received")
                self._responseInfoLabel.setText("Error: No response")
                self._responseInfoLabel.setForeground(Color(255, 100, 100))  # Light red for errors
                
        except Exception as e:
            self._setResponseText("Error: " + str(e))
            self._responseInfoLabel.setText("Error occurred")
            self._responseInfoLabel.setForeground(Color(255, 100, 100))  # Light red for errors
            self._callbacks.printError("Request error: " + str(e))
            
    def _updateAuthFields(self):
        """Update auth fields based on selected type"""
        auth_type = str(self._authTypeCombo.getSelectedItem())
        
        if auth_type == "None":
            self._authKeyLabel.setVisible(False)
            self._authKeyField.setVisible(False)
            self._authValueLabel.setText("Value:")
            self._authValueField.setVisible(False)
            
        elif auth_type == "Bearer Token":
            self._authKeyLabel.setVisible(False)
            self._authKeyField.setVisible(False)
            self._authValueLabel.setText("Token:")
            self._authValueField.setVisible(True)
            
        elif auth_type == "API Key":
            self._authKeyLabel.setText("Header Name:")
            self._authKeyLabel.setVisible(True)
            self._authKeyField.setVisible(True)
            self._authKeyField.setText("X-API-Key")
            self._authValueLabel.setText("API Key:")
            self._authValueField.setVisible(True)
            
        elif auth_type == "Basic Auth":
            self._authKeyLabel.setText("Username:")
            self._authKeyLabel.setVisible(True)
            self._authKeyField.setVisible(True)
            self._authValueLabel.setText("Password:")
            self._authValueField.setVisible(True)
            
        elif auth_type == "Custom Header":
            self._authKeyLabel.setText("Header Name:")
            self._authKeyLabel.setVisible(True)
            self._authKeyField.setVisible(True)
            self._authValueLabel.setText("Header Value:")
            self._authValueField.setVisible(True)
            
    def _applyAuth(self, event):
        """Apply authentication settings"""
        auth_type = str(self._authTypeCombo.getSelectedItem())
        # Clear existing auth headers
        self.auth_headers = {}
        
        if auth_type == "Bearer Token":
            token = self._authValueField.getText().strip()
            if token:
                self.auth_headers["Authorization"] = "Bearer " + token
                
        elif auth_type == "API Key":
            header_name = self._authKeyField.getText().strip()
            api_key = self._authValueField.getText().strip()
            if header_name and api_key:
                self.auth_headers[header_name] = api_key
                
        elif auth_type == "Basic Auth":
            username = self._authKeyField.getText().strip()
            password = self._authValueField.getText().strip()
            if username and password:
                credentials = username + ":" + password
                encoded = base64.b64encode(credentials.encode('utf-8')).decode('utf-8')
                self.auth_headers["Authorization"] = "Basic " + encoded
                
        elif auth_type == "Custom Header":
            header_name = self._authKeyField.getText().strip()
            header_value = self._authValueField.getText().strip()
            if header_name and header_value:
                self.auth_headers[header_name] = header_value
        
        # If auth type is "None", auth_headers will be empty (already cleared above)
                
        # Debug output
        if self.auth_headers:
            self._callbacks.printOutput("Authentication applied: " + str(self.auth_headers))
        else:
            self._callbacks.printOutput("Authentication cleared")
        
        # Refresh headers to show the updated authentication
        self._refreshHeadersFromSpec()
        
        auth_message = "Authentication cleared" if auth_type == "None" else "Authentication settings applied"
        if auth_type != "None" and self.auth_headers:
            header_names = ", ".join(self.auth_headers.keys())
            auth_message += "\nHeaders added: " + header_names
            
        JOptionPane.showMessageDialog(self._mainPanel,
            auth_message, 
            "Success", JOptionPane.INFORMATION_MESSAGE)
            
    def _addHeader(self, event):
        """Add custom header"""
        name = JOptionPane.showInputDialog(self._mainPanel, "Header Name:")
        if name:
            value = JOptionPane.showInputDialog(self._mainPanel, "Header Value:")
            if value:
                self._headersTableModel.addRow([name, value])
                # Refresh headers in API Tester tab
                self._refreshHeadersFromSpec()
                
    def _removeHeader(self, event):
        """Remove selected header"""
        selected = self._headersTable.getSelectedRow()
        if selected >= 0:
            self._headersTableModel.removeRow(selected)
            # Refresh headers in API Tester tab
            self._refreshHeadersFromSpec()
            

        

        

    
    def _updateBaseUrl(self, event):
        """Update the base URL"""
        new_base_url = self._baseUrlField.getText().strip()
        if new_base_url:
            # Remove trailing slash if present
            if new_base_url.endswith('/'):
                new_base_url = new_base_url[:-1]
            
            self.base_url = new_base_url
            
            # Update the API Tester tab's base URL combo box
            if hasattr(self, '_quickBaseUrlCombo'):
                self._quickBaseUrlCombo.setSelectedItem(self.base_url)
            
            # Re-load endpoint details if one is selected
            if self.current_endpoint:
                self._loadEndpointDetails()
                # Also update the request URL field immediately
                self._updateRequestFromParams()
            
            # Update all endpoint URLs in the list to reflect the new base URL
            self._updateAllEndpointUrls()
            
            JOptionPane.showMessageDialog(self._mainPanel,
                "Base URL updated to: " + self.base_url, 
                "Success", JOptionPane.INFORMATION_MESSAGE)
        else:
            JOptionPane.showMessageDialog(self._mainPanel,
                "Please enter a valid base URL", 
                "Error", JOptionPane.ERROR_MESSAGE)
    
    def _quickChangeBaseUrl(self):
        """Quick change base URL from combo box"""
        selected = self._quickBaseUrlCombo.getSelectedItem()
        if selected:
            new_base_url = str(selected).strip()
            if new_base_url and new_base_url != self.base_url:
                # Remove trailing slash if present
                if new_base_url.endswith('/'):
                    new_base_url = new_base_url[:-1]
                
                self.base_url = new_base_url
                self._baseUrlField.setText(self.base_url)
                
                # Re-load endpoint details if one is selected
                if self.current_endpoint:
                    self._loadEndpointDetails()
                    # Also update the request URL field immediately
                    self._updateRequestFromParams()
    
    def _addQueryParam(self, event):
        """Add a new query parameter"""
        name = JOptionPane.showInputDialog(self._mainPanel, "Parameter Name:")
        if name:
            value = JOptionPane.showInputDialog(self._mainPanel, "Parameter Value:")
            if value:
                self._queryParamsTableModel.addRow([name, value, "string", "false", "Custom parameter"])
    
    def _removeQueryParam(self, event):
        """Remove selected query parameter"""
        selected = self._queryParamsTable.getSelectedRow()
        if selected >= 0:
            self._queryParamsTableModel.removeRow(selected)
    
    def _addRequestHeader(self, event):
        """Add a new request header"""
        name = JOptionPane.showInputDialog(self._mainPanel, "Header Name:")
        if name:
            value = JOptionPane.showInputDialog(self._mainPanel, "Header Value:")
            if value:
                self._requestHeadersTableModel.addRow([name, value, "Manual"])
    
    def _removeRequestHeader(self, event):
        """Remove selected request header"""
        selected = self._requestHeadersTable.getSelectedRow()
        if selected >= 0:
            self._requestHeadersTableModel.removeRow(selected)
    
    def _refreshHeadersFromSpec(self, event=None):
        """Refresh headers from the Swagger specification"""
        # Check if the headers table exists (UI might not be fully initialized)
        if not hasattr(self, '_requestHeadersTableModel'):
            return
        
        # Clear existing headers from all sources
        for i in range(self._requestHeadersTableModel.getRowCount() - 1, -1, -1):
            source = self._requestHeadersTableModel.getValueAt(i, 2)
            if source in ["Spec", "Auth", "Global"]:
                self._requestHeadersTableModel.removeRow(i)
        
        # Add header parameters from spec (only if endpoint is selected)
        if self.current_endpoint and hasattr(self, '_headerParamsTableModel'):
            for i in range(self._headerParamsTableModel.getRowCount()):
                name = self._headerParamsTableModel.getValueAt(i, 0)
                value = self._headerParamsTableModel.getValueAt(i, 1)
                if name and value:
                    self._requestHeadersTableModel.addRow([name, value, "Spec"])
        
        # Add global authentication headers (always, regardless of endpoint selection)
        for header, value in self.auth_headers.items():
            if header and value:
                self._requestHeadersTableModel.addRow([header, value, "Auth"])
        
        # Add global custom headers (always, regardless of endpoint selection)
        if hasattr(self, '_headersTableModel'):
            for i in range(self._headersTableModel.getRowCount()):
                name = self._headersTableModel.getValueAt(i, 0)
                value = self._headersTableModel.getValueAt(i, 1)
                if name and value:
                    self._requestHeadersTableModel.addRow([name, value, "Global"])
    
    def _updateRequestFromParams(self, event=None):
        """Update the request URL and headers from parameter tables"""
        if not self.current_endpoint:
            return
        
        # Start with base URL and path
        path = self.current_endpoint["path"]
        
        # Replace path parameters
        for i in range(self._pathParamsTableModel.getRowCount()):
            name = self._pathParamsTableModel.getValueAt(i, 0)
            value = self._pathParamsTableModel.getValueAt(i, 1)
            path = path.replace("{" + str(name) + "}", str(value))
        
        # Build query string
        query_params = []
        for i in range(self._queryParamsTableModel.getRowCount()):
            name = self._queryParamsTableModel.getValueAt(i, 0)
            value = self._queryParamsTableModel.getValueAt(i, 1)
            if name and value:  # Only add non-empty parameters
                query_params.append(str(name) + "=" + str(value))
        
        # Construct full URL
        full_url = self.base_url + path
        if query_params:
            full_url += "?" + "&".join(query_params)
        
        self._requestUrlField.setText(full_url)
        
        # Refresh headers to ensure they're current
        self._refreshHeadersFromSpec()
    
    def _updateAllEndpointUrls(self):
        """Update all endpoint URLs to reflect the current base URL"""
        try:
            # Update the endpoint list to show the new base URL
            if hasattr(self, '_endpointListModel') and self.endpoints:
                # Clear and repopulate the list with updated URLs
                self._endpointListModel.clear()
                for endpoint in self.endpoints:
                    endpoint_text = endpoint["method"] + " " + endpoint["path"]
                    self._endpointListModel.addElement(endpoint_text)
                
                # Update the endpoint count label
                if hasattr(self, '_endpointCountLabel'):
                    count = len(self.endpoints)
                    if count == 0:
                        self._endpointCountLabel.setText("No endpoints found")
                    elif count == 1:
                        self._endpointCountLabel.setText("1 endpoint loaded")
                    else:
                        self._endpointCountLabel.setText(str(count) + " endpoints loaded")
                
                self._callbacks.printOutput("All endpoint URLs updated for new base URL: " + self.base_url)
        except Exception as e:
            self._callbacks.printError("Error updating endpoint URLs: " + str(e))
    
    def _createRequestPopupMenu(self):
        """Create popup menu for request editor"""
        self._requestPopup = JPopupMenu()
        
        # Send to Repeater
        sendToRepeater = JMenuItem("Send to Repeater", actionPerformed=lambda e: self._sendToRepeater())
        self._requestPopup.add(sendToRepeater)
        
        # Send to Intruder
        sendToIntruder = JMenuItem("Send to Intruder", actionPerformed=lambda e: self._sendToIntruder())
        self._requestPopup.add(sendToIntruder)
        
        # Send to Scanner
        sendToScanner = JMenuItem("Send to Scanner", actionPerformed=lambda e: self._sendToScanner())
        self._requestPopup.add(sendToScanner)
        
        # Send to Comparer
        sendToComparer = JMenuItem("Send to Comparer", actionPerformed=lambda e: self._sendToComparer())
        self._requestPopup.add(sendToComparer)
        
        self._requestPopup.addSeparator()
        
        # Copy as curl command
        copyAsCurl = JMenuItem("Copy as curl command", actionPerformed=lambda e: self._copyAsCurl())
        self._requestPopup.add(copyAsCurl)
        
        # Save request
        saveRequest = JMenuItem("Save request to file", actionPerformed=lambda e: self._saveRequest())
        self._requestPopup.add(saveRequest)
    
    def _setRequestText(self, text, force_update=False):
        """Set request text with syntax highlighting"""
        # Prevent recursive calls
        if self._updating_request_text and not force_update:
            return
            
        if not text:
            self._requestEditor.setText("")
            return
        
        self._updating_request_text = True
        
        try:
            # In the Request tab, we only want to show the body content
            # Apply syntax highlighting to just the body content
            if text.strip():
                try:
                    # Detect content type for appropriate highlighting
                    if text.strip().startswith('{') or text.strip().startswith('['):
                        # JSON content - highlight as JSON
                        self.syntax_highlighter.highlight_json(self._requestEditor, text)
                    elif text.strip().startswith('<'):
                        # XML content - highlight as XML
                        self.syntax_highlighter.highlight_xml(self._requestEditor, text)
                    elif '=' in text and '&' in text:
                        # Form data - highlight as form
                        self.syntax_highlighter.highlight_form_data(self._requestEditor, text)
                    else:
                        # Plain text - no special highlighting
                        self._requestEditor.setText(text)
                except Exception as e:
                    # Fallback to plain text
                    self._callbacks.printError("Request highlighting error: " + str(e))
                    self._requestEditor.setText(text)
            else:
                self._requestEditor.setText("")
        
        finally:
            self._updating_request_text = False
    
    def _setResponseText(self, text, status_code=None):
        """Set response text with syntax highlighting"""
        if not text:
            self._responseViewer.setText("")
            return
            
        # If it's already a full HTTP response, highlight it
        if text.startswith("HTTP/"):
            try:
                self.syntax_highlighter.highlight_http_response(self._responseViewer, text)
            except Exception as e:
                self._callbacks.printError("Response highlighting error: " + str(e))
                self._responseViewer.setText(text)
        else:
            # Build a minimal HTTP response for highlighting
            status_line = "HTTP/1.1 " + str(status_code or 200) + " OK\n"
            
            # Detect content type
            content_type = "text/plain"
            if text.strip().startswith('{') or text.strip().startswith('['):
                content_type = "application/json"
            elif text.strip().startswith('<'):
                content_type = "application/xml"
                
            headers = "Content-Type: " + content_type + "\n"
            headers += "Content-Length: " + str(len(text)) + "\n"
            
            full_response = status_line + headers + "\n" + text
            
            try:
                self.syntax_highlighter.highlight_http_response(self._responseViewer, full_response)
            except Exception as e:
                self._callbacks.printError("Response highlighting error: " + str(e))
                self._responseViewer.setText(text)
    
    def _buildCurrentRequest(self):
        """Build the current request as bytes"""
        try:
            # Get request details
            method = str(self._methodCombo.getSelectedItem())
            url = self._requestUrlField.getText()
            body = self._requestEditor.getText()
            content_type = str(self._contentTypeCombo.getSelectedItem())
            
            # Parse URL
            parsed = urlparse(url)
            
            # Build headers
            headers = []
            headers.append(method + " " + parsed.path + ("?" + parsed.query if parsed.query else "") + " HTTP/1.1")
            headers.append("Host: " + parsed.netloc)
            
            # Add content type
            if method in ["POST", "PUT", "PATCH"] and content_type:
                headers.append("Content-Type: " + content_type)
                
            # Add headers from the request headers table (includes spec, auth, global, and manual headers)
            for i in range(self._requestHeadersTableModel.getRowCount()):
                name = self._requestHeadersTableModel.getValueAt(i, 0)
                value = self._requestHeadersTableModel.getValueAt(i, 1)
                if name and value:  # Only add non-empty headers
                    headers.append(str(name) + ": " + str(value))
                
            # Add default headers if enabled
            if self._includeDefaultHeadersCheck.isSelected():
                headers.append("User-Agent: Swagger-API-Tester/1.0")
                headers.append("Accept: */*")
                
            # Build full request
            if body and method in ["POST", "PUT", "PATCH"]:
                headers.append("Content-Length: " + str(len(body)))
                full_request = "\r\n".join(headers) + "\r\n\r\n" + body
            else:
                full_request = "\r\n".join(headers) + "\r\n\r\n"
                
            # Convert to bytes
            return self._helpers.stringToBytes(full_request)
            
        except Exception as e:
            self._callbacks.printError("Error building request: " + str(e))
            return None
    
    def _getHttpService(self):
        """Get HTTP service from current URL"""
        try:
            url = self._requestUrlField.getText()
            parsed = urlparse(url)
            host = parsed.hostname
            port = parsed.port if parsed.port else (443 if parsed.scheme == "https" else 80)
            use_https = parsed.scheme == "https"
            
            return self._helpers.buildHttpService(host, port, use_https)
        except:
            return None
    
    def _sendToRepeater(self):
        """Send current request to Repeater"""
        request_bytes = self._buildCurrentRequest()
        http_service = self._getHttpService()
        
        if request_bytes and http_service:
            self._callbacks.sendToRepeater(
                http_service.getHost(),
                http_service.getPort(),
                http_service.getProtocol() == "https",
                request_bytes,
                "Swagger API Tester"
            )
            self._callbacks.printOutput("Request sent to Repeater")
    
    def _sendToIntruder(self):
        """Send current request to Intruder"""
        request_bytes = self._buildCurrentRequest()
        http_service = self._getHttpService()
        
        if request_bytes and http_service:
            self._callbacks.sendToIntruder(
                http_service.getHost(),
                http_service.getPort(),
                http_service.getProtocol() == "https",
                request_bytes
            )
            self._callbacks.printOutput("Request sent to Intruder")
    
    def _sendToScanner(self):
        """Send current request to Scanner"""
        request_bytes = self._buildCurrentRequest()
        http_service = self._getHttpService()
        
        if request_bytes and http_service:
            # Check if it's a GET request (Scanner typically needs a baseline request)
            method = str(self._methodCombo.getSelectedItem())
            if method != "GET":
                result = JOptionPane.showConfirmDialog(self._mainPanel,
                    "Scanner typically works best with GET requests.\nDo you want to continue?",
                    "Non-GET Request", JOptionPane.YES_NO_OPTION)
                if result != JOptionPane.YES_OPTION:
                    return
            
            # Create a request-response pair (Scanner needs this)
            self._callbacks.doActiveScan(
                http_service.getHost(),
                http_service.getPort(),
                http_service.getProtocol() == "https",
                request_bytes
            )
            self._callbacks.printOutput("Request sent to Scanner")
    
    def _sendToComparer(self):
        """Send current request to Comparer"""
        request_bytes = self._buildCurrentRequest()
        
        if request_bytes:
            self._callbacks.sendToComparer(request_bytes)
            self._callbacks.printOutput("Request sent to Comparer")
    
    def _copyAsCurl(self):
        """Copy request as curl command"""
        try:
            method = str(self._methodCombo.getSelectedItem())
            url = self._requestUrlField.getText()
            body = self._requestEditor.getText()
            content_type = str(self._contentTypeCombo.getSelectedItem())
            
            # Build curl command
            curl_cmd = "curl"
            
            # Add method
            if method != "GET":
                curl_cmd += " -X " + method
            
            # Add headers
            if content_type and method in ["POST", "PUT", "PATCH"]:
                curl_cmd += " -H 'Content-Type: " + content_type + "'"
            
            # Add headers from the request headers table
            for i in range(self._requestHeadersTableModel.getRowCount()):
                name = self._requestHeadersTableModel.getValueAt(i, 0)
                value = self._requestHeadersTableModel.getValueAt(i, 1)
                if name and value:
                    curl_cmd += " -H '" + str(name) + ": " + str(value) + "'"
            
            # Add body
            if body and method in ["POST", "PUT", "PATCH"]:
                # Escape single quotes in body
                escaped_body = body.replace("'", "'\"'\"'")
                curl_cmd += " -d '" + escaped_body + "'"
            
            # Add URL
            curl_cmd += " '" + url + "'"
            
            # Copy to clipboard
            from java.awt.datatransfer import StringSelection
            from java.awt import Toolkit
            
            selection = StringSelection(curl_cmd)
            clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
            clipboard.setContents(selection, None)
            
            JOptionPane.showMessageDialog(self._mainPanel,
                "curl command copied to clipboard",
                "Success", JOptionPane.INFORMATION_MESSAGE)
            
        except Exception as e:
            self._callbacks.printError("Error copying as curl: " + str(e))
    
    def _saveRequest(self):
        """Save request to file"""
        chooser = JFileChooser()
        chooser.setSelectedFile(JavaFile("api_request.txt"))
        
        if chooser.showSaveDialog(self._mainPanel) == JFileChooser.APPROVE_OPTION:
            file = chooser.getSelectedFile()
            try:
                request_bytes = self._buildCurrentRequest()
                if request_bytes:
                    with open(file.getAbsolutePath(), 'wb') as f:
                        f.write(self._helpers.bytesToString(request_bytes))
                    JOptionPane.showMessageDialog(self._mainPanel,
                        "Request saved successfully",
                        "Success", JOptionPane.INFORMATION_MESSAGE)
            except Exception as e:
                JOptionPane.showMessageDialog(self._mainPanel,
                    "Error saving request: " + str(e),
                    "Error", JOptionPane.ERROR_MESSAGE)
    
    # IContextMenuFactory implementation
    def createMenuItems(self, invocation):
        """Create context menu items for Burp"""
        menu_items = []
        
        # Only show menu for requests in our extension
        if invocation.getInvocationContext() == invocation.CONTEXT_MESSAGE_EDITOR_REQUEST:
            menu_item = JMenuItem("Send to Swagger API Tester", 
                                actionPerformed=lambda e: self._loadFromContextMenu(invocation))
            menu_items.append(menu_item)
        
        return menu_items if menu_items else None
    
    def _loadFromContextMenu(self, invocation):
        """Load request from context menu into the extension"""
        try:
            # Get the selected request
            messages = invocation.getSelectedMessages()
            if messages and len(messages) > 0:
                message = messages[0]
                request = message.getRequest()
                http_service = message.getHttpService()
                
                # Parse the request
                request_info = self._helpers.analyzeRequest(http_service, request)
                headers = request_info.getHeaders()
                body_offset = request_info.getBodyOffset()
                body = self._helpers.bytesToString(request[body_offset:])
                
                # Extract method and path
                first_line = headers[0].split(' ')
                method = first_line[0]
                path = first_line[1]
                
                # Build full URL
                url = http_service.getProtocol() + "://" + http_service.getHost()
                if (http_service.getPort() != 80 and http_service.getProtocol() == "http") or \
                   (http_service.getPort() != 443 and http_service.getProtocol() == "https"):
                    url += ":" + str(http_service.getPort())
                url += path
                
                # Load into API tester
                self._methodCombo.setSelectedItem(method)
                self._requestUrlField.setText(url)
                self._setRequestText(body)
                
                # Extract content-type
                for header in headers[1:]:
                    if header.lower().startswith("content-type:"):
                        content_type = header.split(":", 1)[1].strip()
                        # Try to match with combo box items
                        for i in range(self._contentTypeCombo.getItemCount()):
                            if content_type.lower().startswith(self._contentTypeCombo.getItemAt(i).lower()):
                                self._contentTypeCombo.setSelectedIndex(i)
                                break
                
                # Switch to API Tester tab
                self._tabbedPane.setSelectedIndex(1)
                
                self._callbacks.printOutput("Request loaded from context menu")
                
        except Exception as e:
            self._callbacks.printError("Error loading from context menu: " + str(e))
    
    # ITab implementation
    def getTabCaption(self):
        return "Swagger API Tester"
        
    def getUiComponent(self):
        return self._mainPanel
        
    # IHttpListener implementation
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # We can optionally process HTTP messages here
        pass
        
    # IMessageEditorController implementation
    def getHttpService(self):
        return None
        
    def getRequest(self):
        return None
        
    def getResponse(self):
        return None

    def _prettyPrintRequest(self, event):
        """Pretty print JSON/XML in request body"""
        try:
            # Get current text from the editor
            current_text = self._requestEditor.getText()
            
            # Extract just the body part if it's a full HTTP request
            body_text = current_text
            if current_text.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'PATCH ', 'HEAD ', 'OPTIONS ')):
                lines = current_text.split('\n')
                # Find the empty line that separates headers from body
                body_start = -1
                for i, line in enumerate(lines):
                    if not line.strip():
                        body_start = i + 1
                        break
                if body_start != -1 and body_start < len(lines):
                    body_text = '\n'.join(lines[body_start:])
            
            if not body_text.strip():
                return
                
            # Try to format as JSON first
            try:
                import json
                parsed = json.loads(body_text)
                formatted = json.dumps(parsed, indent=2, separators=(',', ': '))
                self._setRequestText(formatted)
                return
            except:
                pass
            
            # Try to format as XML
            try:
                import xml.etree.ElementTree as ET
                from xml.dom import minidom
                
                root = ET.fromstring(body_text)
                rough_string = ET.tostring(root, encoding='unicode')
                reparsed = minidom.parseString(rough_string)
                formatted = reparsed.toprettyxml(indent="  ")
                # Remove empty lines
                formatted = '\n'.join(line for line in formatted.split('\n') if line.strip())
                self._setRequestText(formatted)
                return
            except:
                pass
                
            JOptionPane.showMessageDialog(self._mainPanel,
                "Could not format the request body. Make sure it's valid JSON or XML.",
                "Format Error", JOptionPane.WARNING_MESSAGE)
                
        except Exception as e:
            JOptionPane.showMessageDialog(self._mainPanel,
                "Error formatting request: " + str(e),
                "Format Error", JOptionPane.ERROR_MESSAGE)
    
    def _minifyRequest(self, event):
        """Minify JSON/XML in request body"""
        try:
            # Get current text from the editor
            current_text = self._requestEditor.getText()
            
            # Extract just the body part if it's a full HTTP request
            body_text = current_text
            if current_text.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'PATCH ', 'HEAD ', 'OPTIONS ')):
                lines = current_text.split('\n')
                # Find the empty line that separates headers from body
                body_start = -1
                for i, line in enumerate(lines):
                    if not line.strip():
                        body_start = i + 1
                        break
                if body_start != -1 and body_start < len(lines):
                    body_text = '\n'.join(lines[body_start:])
            
            if not body_text.strip():
                return
                
            # Try to minify as JSON first
            try:
                import json
                parsed = json.loads(body_text)
                minified = json.dumps(parsed, separators=(',', ':'))
                self._setRequestText(minified)
                return
            except:
                pass
            
            # Try to minify as XML
            try:
                import xml.etree.ElementTree as ET
                root = ET.fromstring(body_text)
                minified = ET.tostring(root, encoding='unicode')
                # Remove extra whitespace
                import re
                minified = re.sub(r'>\s+<', '><', minified)
                self._setRequestText(minified)
                return
            except:
                pass
                
            JOptionPane.showMessageDialog(self._mainPanel,
                "Could not minify the request body. Make sure it's valid JSON or XML.",
                "Minify Error", JOptionPane.WARNING_MESSAGE)
                
        except Exception as e:
            JOptionPane.showMessageDialog(self._mainPanel,
                "Error minifying request: " + str(e),
                "Minify Error", JOptionPane.ERROR_MESSAGE)
    
    def _highlightRequest(self, event):
        """Apply syntax highlighting to current request"""
        try:
            current_text = self._requestEditor.getText()
            if current_text.strip():
                # Force update the highlighting
                self._setRequestText(current_text, force_update=True)
            else:
                # If no text, just clear the editor
                self._requestEditor.setText("")
        except Exception as e:
            JOptionPane.showMessageDialog(self._mainPanel,
                "Error applying syntax highlighting: " + str(e),
                "Highlight Error", JOptionPane.ERROR_MESSAGE)
    
    def _toggleTheme(self, event):
        """Toggle between Burp and Dark themes"""
        try:
            new_theme = self.syntax_highlighter.switch_theme()
            
            # Update button text
            if new_theme == "burp":
                self._themeButton.setText("Burp Theme")
            else:
                self._themeButton.setText("Dark Theme")
            
            # Re-apply highlighting to current content
            current_request = self._requestEditor.getText()
            current_response = self._responseViewer.getText()
            
            if current_request.strip():
                self._setRequestText(current_request, force_update=True)
            
            if current_response.strip():
                # Re-highlight response
                if current_response.startswith("HTTP/"):
                    try:
                        self.syntax_highlighter.highlight_http_response(self._responseViewer, current_response)
                    except Exception as e:
                        self._callbacks.printError("Response re-highlighting error: " + str(e))
                
            JOptionPane.showMessageDialog(self._mainPanel,
                "Switched to " + new_theme.title() + " theme",
                "Theme Changed", JOptionPane.INFORMATION_MESSAGE)
                
        except Exception as e:
            JOptionPane.showMessageDialog(self._mainPanel,
                "Error switching theme: " + str(e),
                "Theme Error", JOptionPane.ERROR_MESSAGE)



class RequestMouseListener(MouseAdapter):
    """Mouse listener for request editor popup menu"""
    def __init__(self, extender):
        self.extender = extender
        
    def mousePressed(self, event):
        self._showPopupIfNeeded(event)
        
    def mouseReleased(self, event):
        self._showPopupIfNeeded(event)
        
    def _showPopupIfNeeded(self, event):
        if event.isPopupTrigger():
            self.extender._requestPopup.show(event.getComponent(), event.getX(), event.getY())

class RequestDocumentListener(DocumentListener):
    """Document listener for request editor to trigger syntax highlighting"""
    
    def __init__(self, extender):
        self.extender = extender
        self.update_timer = None
    
    def insertUpdate(self, event):
        self._scheduleHighlightUpdate()
    
    def removeUpdate(self, event):
        self._scheduleHighlightUpdate()
    
    def changedUpdate(self, event):
        self._scheduleHighlightUpdate()
    
    def _scheduleHighlightUpdate(self):
        """Schedule a syntax highlighting update with a small delay to avoid too many updates"""
        if self.update_timer:
            self.update_timer.stop()
        
        # Use a timer to delay the highlighting update slightly
        from javax.swing import Timer
        self.update_timer = Timer(300, lambda e: self._updateHighlighting())
        self.update_timer.setRepeats(False)
        self.update_timer.start()
    
    def _updateHighlighting(self):
        """Update syntax highlighting for the request editor"""
        try:
            # Get current text from the editor
            current_text = self.extender._requestEditor.getText()
            
            # Don't re-highlight if this looks like it's already highlighted HTTP request
            if current_text and (current_text.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'PATCH ', 'HEAD ', 'OPTIONS ')) or 'HTTP/1.1' in current_text):
                return
            
            # Only highlight if it's pure body content that user is editing
            if current_text and current_text.strip():
                # Update the request with highlighting (this will add HTTP structure)
                self.extender._setRequestText(current_text)
        except Exception as e:
            # Silently ignore highlighting errors during editing
            pass
