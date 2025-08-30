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
from java.awt import BorderLayout, GridBagLayout, GridBagConstraints, Insets, Font, Color, Dimension, FlowLayout
from java.awt.event import ActionListener, MouseAdapter, KeyEvent, KeyAdapter
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
        
        # Initialize authentication profiles
        self.auth_profiles = []
        self.auth_headers = {}
        
        # Initialize custom headers
        self.custom_headers = []
    
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
        
        # Tab 3: Bulk Testing
        self._bulkTestingTab = self._createBulkTestingTab()
        self._tabbedPane.addTab("Bulk Testing", self._bulkTestingTab)
        
        # Tab 4: Settings
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
        testButton = JButton("Test Parser", actionPerformed=self._testParser)
        
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
                    .addComponent(fileButton)
                    .addComponent(testButton))
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
                    .addComponent(fileButton)
                    .addComponent(testButton))
                .addComponent(exampleLabel)
                .addComponent(exampleText)
                .addComponent(self._progressBar)
        )
        
        # Center panel for parsed endpoints
        centerPanel = JPanel(BorderLayout())
        centerPanel.setBorder(BorderFactory.createTitledBorder("Parsed Endpoints"))
        
        # Endpoints table
        self._endpointsTableModel = DefaultTableModel(["Method", "Path", "Tags", "Description"], 0)
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
        
    # Bulk Testing Methods
    def _startBulkTesting(self, event):
        """Start bulk testing of all endpoints"""
        if not hasattr(self, 'endpoints') or not self.endpoints:
            JOptionPane.showMessageDialog(self._mainPanel,
                "No endpoints loaded. Please import a Swagger specification first.",
                "No Endpoints", JOptionPane.WARNING_MESSAGE)
            return
        
        if self._bulkTestingActive:
            JOptionPane.showMessageDialog(self._mainPanel,
                "Bulk testing is already running. Please stop it first.",
                "Already Running", JOptionPane.INFORMATION_MESSAGE)
            return
        
        # Get options
        try:
            delay = int(self._bulkDelayField.getText())
            timeout = int(self._bulkTimeoutField.getText())
        except ValueError:
            JOptionPane.showMessageDialog(self._mainPanel,
                "Please enter valid numbers for delay and timeout.",
                "Invalid Input", JOptionPane.ERROR_MESSAGE)
            return
        
        # Confirm start
        result = JOptionPane.showConfirmDialog(self._mainPanel,
            "Start bulk testing of {} endpoints?\n\n".format(len(self.endpoints)) +
            "Delay: {}ms\nTimeout: {}ms\n\n".format(delay, timeout) +
            "This will send requests to all endpoints sequentially.",
            "Start Bulk Testing", JOptionPane.YES_NO_OPTION)
        
        if result != JOptionPane.YES_OPTION:
            return
        
        # Start bulk testing
        self._bulkTestingActive = True
        self._bulkTestingPaused = False
        self._bulkTestingStopped = False
        self._bulkResults = []
        self._bulkResultsTableModel.setRowCount(0)
        self._bulkCurrentIndex = 0  # Track current endpoint index for resume
        
        # Update UI
        self._bulkProgressBar.setString("Starting...")
        self._bulkStatusLabel.setText("Testing in progress...")
        self._bulkStatusLabel.setForeground(Color(76, 175, 80))
        
        # Update button states
        self._updateBulkTestingButtonStates()
        
        # Start testing thread
        self._bulkTestingThread = Thread(target=self._runBulkTesting, args=(delay, timeout))
        self._bulkTestingThread.start()
    
    def _stopBulkTesting(self, event):
        """Stop bulk testing"""
        if not self._bulkTestingActive:
            return
        
        # Confirm stop
        result = JOptionPane.showConfirmDialog(self._mainPanel,
            "Are you sure you want to stop bulk testing?\n\n" +
            "This will completely stop the testing process.",
            "Stop Bulk Testing", JOptionPane.YES_NO_OPTION)
        
        if result != JOptionPane.YES_OPTION:
            return
        
        self._bulkTestingActive = False
        self._bulkTestingPaused = False
        self._bulkTestingStopped = True
        self._bulkProgressBar.setString("Stopped")
        self._bulkStatusLabel.setText("Testing stopped by user")
        self._bulkStatusLabel.setForeground(Color(244, 67, 54))
        
        # Update button states
        self._updateBulkTestingButtonStates()
        
        if self._bulkTestingThread and self._bulkTestingThread.is_alive():
            self._bulkTestingThread.join(timeout=1.0)
    
    def _pauseBulkTesting(self, event):
        """Pause bulk testing"""
        if not self._bulkTestingActive or self._bulkTestingPaused:
            return
        
        self._bulkTestingPaused = True
        self._bulkProgressBar.setString("Paused")
        self._bulkStatusLabel.setText("Testing paused - click Resume to continue")
        self._bulkStatusLabel.setForeground(Color(255, 152, 0))  # Orange
        
        # Update button states and summary
        self._updateBulkTestingButtonStates()
        self._updateBulkSummary()
    
    def _resumeBulkTesting(self, event):
        """Resume bulk testing"""
        if not self._bulkTestingActive or not self._bulkTestingPaused:
            return
        
        self._bulkTestingPaused = False
        self._bulkProgressBar.setString("Resuming...")
        self._bulkStatusLabel.setText("Testing resumed...")
        self._bulkStatusLabel.setForeground(Color(76, 175, 80))  # Green
        
        # Update button states and summary
        self._updateBulkTestingButtonStates()
        self._updateBulkSummary()
    
    def _restartBulkTesting(self, event):
        """Restart bulk testing from the beginning"""
        if self._bulkTestingActive:
            # Stop current testing first
            self._stopBulkTesting(None)
        
        # Wait a moment for the thread to stop
        if hasattr(self, '_bulkTestingThread') and self._bulkTestingThread and self._bulkTestingThread.is_alive():
            self._bulkTestingThread.join(timeout=2.0)
        
        # Reset state
        self._bulkTestingStopped = False
        self._bulkCurrentIndex = 0
        
        # Start fresh
        self._startBulkTesting(None)
    
    def _updateBulkTestingButtonStates(self):
        """Update button states based on current testing status"""
        try:
            if hasattr(self, '_startBulkButton'):
                self._startBulkButton.setEnabled(not self._bulkTestingActive)
            
            if hasattr(self, '_pauseBulkButton'):
                self._pauseBulkButton.setEnabled(self._bulkTestingActive and not self._bulkTestingPaused)
            
            if hasattr(self, '_resumeBulkButton'):
                self._resumeBulkButton.setEnabled(self._bulkTestingActive and self._bulkTestingPaused)
            
            if hasattr(self, '_stopBulkButton'):
                self._stopBulkButton.setEnabled(self._bulkTestingActive)
            
            if hasattr(self, '_restartBulkButton'):
                self._restartBulkButton.setEnabled(not self._bulkTestingActive)
                
        except Exception as e:
            self._callbacks.printError("Error updating button states: " + str(e))
    
    def _clearBulkResults(self, event):
        """Clear bulk testing results"""
        self._bulkResults = []
        self._bulkResultsTableModel.setRowCount(0)
        self._bulkSummaryLabel.setText("Results cleared")
        self._bulkProgressBar.setString("Ready")
        self._bulkStatusLabel.setText("No testing started")
        self._bulkStatusLabel.setForeground(Color(100, 100, 100))
        
        # Reset state variables
        self._bulkCurrentIndex = 0
        self._bulkTestingStopped = False
        
        # Update button states
        self._updateBulkTestingButtonStates()
        
        # Disable export button since no results
        if hasattr(self, '_exportButton'):
            self._exportButton.setEnabled(False)
    
    def _runBulkTesting(self, delay, timeout):
        """Run the bulk testing in a separate thread"""
        try:
            total_endpoints = len(self.endpoints)
            completed = self._bulkCurrentIndex  # Start from current index for resume
            
            # Loop through endpoints starting from current index
            for i in range(self._bulkCurrentIndex, total_endpoints):
                # Check if testing was stopped
                if self._bulkTestingStopped:
                    break
                
                # Check if testing is paused
                while self._bulkTestingPaused and not self._bulkTestingStopped:
                    time.sleep(0.1)  # Small delay while paused
                
                # Check if testing was stopped while paused
                if self._bulkTestingStopped:
                    break
                
                # Update current index for resume functionality
                self._bulkCurrentIndex = i
                
                try:
                    endpoint = self.endpoints[i]
                    
                    # Test this endpoint
                    result = self._testSingleEndpoint(endpoint, timeout)
                    self._bulkResults.append(result)
                    
                    # Add result to table
                    self._addBulkResultToTable(result)
                    
                    # Enable export button since we now have results
                    if hasattr(self, '_exportButton'):
                        self._exportButton.setEnabled(True)
                    
                    # Update progress
                    completed += 1
                    progress = int((completed / total_endpoints) * 100)
                    
                    # Update progress bar on EDT
                    try:
                        from javax.swing import SwingUtilities
                        SwingUtilities.invokeLater(lambda: self._updateBulkProgress(progress, completed, total_endpoints))
                    except:
                        # Fallback: update directly
                        self._updateBulkProgress(progress, completed, total_endpoints)
                    
                    # Delay before next request (only if not paused and not stopped)
                    if completed < total_endpoints and not self._bulkTestingPaused and not self._bulkTestingStopped:
                        time.sleep(delay / 1000.0)
                        
                except Exception as e:
                    # Log error and continue
                    error_result = {
                        "status": "Error",
                        "method": endpoint.get("method", "UNKNOWN"),
                        "path": endpoint.get("path", "UNKNOWN"),
                        "response_code": "N/A",
                        "response_time": "N/A",
                        "size": "N/A",
                        "notes": "Error: {}".format(str(e)),
                        "request": "Failed to build request",
                        "response": "No response due to error"
                    }
                    self._bulkResults.append(error_result)
                    self._addBulkResultToTable(error_result)
                    
                    # Enable export button since we now have results
                    if hasattr(self, '_exportButton'):
                        self._exportButton.setEnabled(True)
                    
                    completed += 1
            
            # Testing completed (only if not stopped)
            if not self._bulkTestingStopped:
                try:
                    from javax.swing import SwingUtilities
                    SwingUtilities.invokeLater(lambda: self._bulkTestingCompleted())
                except:
                    # Fallback: call directly
                    self._bulkTestingCompleted()
            
        except Exception as e:
            self._callbacks.printError("Error in bulk testing: " + str(e))
            if not self._bulkTestingStopped:
                try:
                    from javax.swing import SwingUtilities
                    SwingUtilities.invokeLater(lambda: self._bulkTestingCompleted())
                except:
                    # Fallback: call directly
                    self._bulkTestingCompleted()
    
    def _testSingleEndpoint(self, endpoint, timeout):
        """Test a single endpoint and return results with timeout handling"""
        start_time = time.time()
        
        try:
            # Set the current endpoint so we can use the existing request building logic
            self.current_endpoint = endpoint
            self._loadEndpointDetails()
            
            # Build request using the same logic as API Tester tab
            request_bytes = self._buildCurrentRequest()
            http_service = self._getHttpService()
            
            if not request_bytes or not http_service:
                return {
                    "status": "Error",
                    "method": endpoint["method"],
                    "path": endpoint["path"],
                    "response_code": "N/A",
                    "response_time": "N/A",
                    "size": "N/A",
                    "notes": "Failed to build request"
                }
            
            # Implement timeout handling using threading
            # Use a mutable object to store shared variables (Jython compatibility)
            shared_state = {
                'response': None,
                'request_completed': False,
                'request_error': None
            }
            
            def make_request():
                try:
                    shared_state['response'] = self._callbacks.makeHttpRequest(http_service, request_bytes)
                    shared_state['request_completed'] = True
                except Exception as e:
                    shared_state['request_error'] = e
                    shared_state['request_completed'] = True
            
            # Start request in a separate thread
            request_thread = Thread(target=make_request)
            request_thread.daemon = True
            request_thread.start()
            
            # Wait for request to complete or timeout
            request_thread.join(timeout / 1000.0)  # Convert ms to seconds
            
            # Calculate response time
            response_time = int((time.time() - start_time) * 1000)
            
            # Check if request timed out
            if not shared_state['request_completed']:
                return {
                    "status": "Timeout",
                    "method": endpoint["method"],
                    "path": endpoint["path"],
                    "response_code": "Timeout",
                    "response_time": "{}ms".format(response_time),
                    "size": "N/A",
                    "notes": "Request timed out after {}ms".format(timeout),
                    "request": self._helpers.bytesToString(request_bytes),
                    "response": "Request timed out"
                }
            
            # Check if there was an error
            if shared_state['request_error']:
                return {
                    "status": "Error",
                    "method": endpoint["method"],
                    "path": endpoint["path"],
                    "response_code": "N/A",
                    "response_time": "{}ms".format(response_time),
                    "size": "N/A",
                    "notes": "Request error: {}".format(str(shared_state['request_error'])),
                    "request": self._helpers.bytesToString(request_bytes),
                    "response": "Request failed due to error"
                }
            
            # Process successful response
            if shared_state['response']:
                response_info = self._helpers.analyzeResponse(shared_state['response'].getResponse())
                status_code = response_info.getStatusCode()
                response_size = len(shared_state['response'].getResponse())
                
                # Get request and response data for export
                request_data = self._helpers.bytesToString(request_bytes)
                response_data = self._helpers.bytesToString(shared_state['response'].getResponse())
                
                return {
                    "status": "Success",
                    "method": endpoint["method"],
                    "path": endpoint["path"],
                    "response_code": status_code,
                    "response_time": "{}ms".format(response_time),
                    "size": response_size,
                    "notes": "Response received",
                    "request": request_data,
                    "response": response_data
                }
            else:
                # Get request data for export even if no response
                request_data = self._helpers.bytesToString(request_bytes)
                
                return {
                    "status": "Error",
                    "method": endpoint["method"],
                    "path": endpoint["path"],
                    "response_code": "No Response",
                    "response_time": "{}ms".format(response_time),
                    "size": "N/A",
                    "notes": "No response received",
                    "request": request_data,
                    "response": "No response received"
                }
            
        except Exception as e:
            return {
                "status": "Error",
                "method": endpoint.get("method", "UNKNOWN"),
                "path": endpoint.get("path", "UNKNOWN"),
                "response_code": "N/A",
                "response_time": "N/A",
                "size": "N/A",
                "notes": "Error: {}".format(str(e)),
                "request": "Failed to build request",
                "response": "No response due to error"
            }
    
    def _addBulkResultToTable(self, result):
        """Add a bulk testing result to the results table"""
        try:
            # Add row to table model
            row_data = [
                result["status"],
                result["method"],
                result["path"],
                result["response_code"],
                result["response_time"],
                result["size"],
                result["notes"]
            ]
            
            # Add to table on EDT
            try:
                from javax.swing import SwingUtilities
                SwingUtilities.invokeLater(lambda: self._bulkResultsTableModel.addRow(row_data))
            except:
                # Fallback: add directly
                self._bulkResultsTableModel.addRow(row_data)
            
        except Exception as e:
            self._callbacks.printError("Error adding result to table: " + str(e))
    
    def _updateBulkProgress(self, progress, completed, total):
        """Update bulk testing progress on EDT"""
        try:
            self._bulkProgressBar.setValue(progress)
            
            # Show current status including pause/resume info
            if hasattr(self, '_bulkTestingPaused') and self._bulkTestingPaused:
                self._bulkProgressBar.setString("PAUSED: {}/{} ({}%)".format(completed, total, progress))
            else:
                self._bulkProgressBar.setString("{}/{} ({}%)".format(completed, total, progress))
            
            self._bulkStatusLabel.setText("Testing... {}/{} completed".format(completed, total))
        except Exception as e:
            self._callbacks.printError("Error updating progress: " + str(e))
    
    def _bulkTestingCompleted(self):
        """Handle bulk testing completion"""
        try:
            self._bulkTestingActive = False
            self._bulkTestingPaused = False
            self._bulkProgressBar.setString("Completed")
            self._bulkStatusLabel.setText("Testing completed")
            self._bulkStatusLabel.setForeground(Color(76, 175, 80))
            
            # Update summary
            total = len(self._bulkResults)
            success_count = len([r for r in self._bulkResults if r["status"] == "Success"])
            error_count = len([r for r in self._bulkResults if r["status"] == "Error"])
            
            summary = "Completed: {} endpoints tested. Success: {}, Errors: {}".format(total, success_count, error_count)
            self._bulkSummaryLabel.setText(summary)
            
            # Update button states
            self._updateBulkTestingButtonStates()
            
            # Enable export button since we now have results
            if hasattr(self, '_exportButton'):
                self._exportButton.setEnabled(True)
                
            # Update summary to show export availability
            self._updateBulkSummary()
            
        except Exception as e:
            self._callbacks.printError("Error in completion handler: " + str(e))
    
    def _exportBulkResults(self, event):
        """Export bulk testing results to files in chunks"""
        try:
            if not hasattr(self, '_bulkResults') or not self._bulkResults:
                JOptionPane.showMessageDialog(self._mainPanel,
                    "No results to export. Please run bulk testing first.",
                    "No Results", JOptionPane.WARNING_MESSAGE)
                return
            
            # Get chunk size
            try:
                chunk_size = int(self._exportChunkField.getText())
                if chunk_size <= 0:
                    raise ValueError("Chunk size must be positive")
            except ValueError:
                JOptionPane.showMessageDialog(self._mainPanel,
                    "Please enter a valid chunk size (positive number).",
                    "Invalid Chunk Size", JOptionPane.ERROR_MESSAGE)
                return
            
            # Create file chooser for export directory
            from javax.swing import JFileChooser
            from java.io import File
            
            fileChooser = JFileChooser()
            fileChooser.setDialogTitle("Select Export Directory")
            fileChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY)
            
            result = fileChooser.showOpenDialog(self._mainPanel)
            if result != JFileChooser.APPROVE_OPTION:
                return
            
            export_dir = fileChooser.getSelectedFile()
            
            # Get export type and status filter
            export_type = self._exportTypeCombo.getSelectedItem()
            status_filter = self._statusFilterField.getText().strip()
            
            # Parse status filter (e.g., "200,401,503" or "200, 401, 503")
            status_codes = set()
            if status_filter:
                for code in status_filter.replace(" ", "").split(","):
                    if code.isdigit():
                        status_codes.add(int(code))
            
            # Filter results based on export type and status codes
            filtered_results = []
            for result in self._bulkResults:
                # Apply status code filter if specified
                if status_codes:
                    response_code = result.get("response_code", "")
                    if isinstance(response_code, str) and response_code.isdigit():
                        if int(response_code) not in status_codes:
                            continue
                    elif response_code not in status_codes:
                        continue
                
                filtered_results.append(result)
            
            # Group by unique API paths first
            unique_paths = set()
            path_results = {}
            
            for result in filtered_results:
                path = result.get("path", "")
                if path:
                    unique_paths.add(path)
                    if path not in path_results:
                        path_results[path] = []
                    path_results[path].append(result)
            
            # Sort unique paths
            sorted_paths = sorted(unique_paths)
            total_unique_paths = len(sorted_paths)
            
            # Group unique paths by chunks
            total_files = (total_unique_paths + chunk_size - 1) // chunk_size  # Ceiling division
            
            exported_files = []
            
            for file_index in range(total_files):
                start_idx = file_index * chunk_size
                end_idx = min(start_idx + chunk_size, total_unique_paths)
                chunk_paths = sorted_paths[start_idx:end_idx]
                
                # Get all results for these paths
                chunk_results = []
                for path in chunk_paths:
                    chunk_results.extend(path_results[path])
                
                # Create filename with base URL
                base_url = self._baseUrlField.getText() if hasattr(self, '_baseUrlField') else "unknown"
                if base_url:
                    # Clean the base URL for filename (remove protocol, replace special chars)
                    clean_base = base_url.replace("https://", "").replace("http://", "").replace("://", "")
                    clean_base = clean_base.replace("/", "_").replace(":", "_").replace(".", "_")
                    if clean_base.endswith("_"):
                        clean_base = clean_base[:-1]
                    filename = "{}_chunk_{:02d}_of_{:02d}.txt".format(clean_base, file_index + 1, total_files)
                else:
                    filename = "bulk_testing_chunk_{:02d}_of_{:02d}.txt".format(file_index + 1, total_files)
                file_path = File(export_dir, filename)
                
                                # Write chunk to file with UTF-8 encoding for better Unicode support
                # Write chunk to file (Jython compatible)
                with open(str(file_path), 'w') as f:
                    f.write("BULK TESTING RESULTS - CHUNK {} OF {}\n".format(file_index + 1, total_files))
                    f.write("=" * 80 + "\n\n")
                    
                    # Write export metadata
                    f.write("EXPORT METADATA:\n")
                    f.write("-" * 40 + "\n")
                    f.write("Export Date: {}\n".format(time.strftime("%Y-%m-%d %H:%M:%S")))
                    f.write("Export Type: {}\n".format(export_type))
                    if status_filter:
                        f.write("Status Filter: {}\n".format(status_filter))
                    f.write("Unique API Paths in Chunk: {}\n".format(len(chunk_paths)))
                    f.write("Total HTTP Requests in Chunk: {}\n".format(len(chunk_results)))
                    f.write("Chunk Size Setting: {} (unique paths)\n".format(chunk_size))
                    f.write("\n")
                    
                    # List all APIs in this chunk with HTTP methods
                    f.write("APIs in this chunk:\n")
                    f.write("-" * 40 + "\n")
                    
                    # Group by path and collect HTTP methods
                    path_methods = {}
                    for result in chunk_results:
                        path = result.get("path", "")
                        method = result.get("method", "")
                        if path and method:
                            if path not in path_methods:
                                path_methods[path] = set()
                            path_methods[path].add(method)
                    
                    # Sort paths and display with methods in straight column format
                    for path in sorted(path_methods.keys()):
                        methods = sorted(path_methods[path])
                        methods_str = ",".join(methods)
                        # Use consistent spacing for straight column alignment
                        f.write("{:<25} {}\n".format(methods_str, path))
                    f.write("\n")
                    
                    # Write detailed results
                    f.write("DETAILED RESULTS:\n")
                    f.write("=" * 80 + "\n\n")
                    
                    for i, result in enumerate(chunk_results, 1):
                        f.write("Result {} of {} in this chunk:\n".format(i, len(chunk_results)))
                        f.write("-" * 50 + "\n")
                        
                        # Basic info
                        f.write("Method: {}\n".format(result.get("method", "N/A")))
                        f.write("Path: {}\n".format(result.get("path", "N/A")))
                        f.write("Status: {}\n".format(result.get("status", "N/A")))
                        f.write("Response Code: {}\n".format(result.get("response_code", "N/A")))
                        f.write("Response Time: {} ms\n".format(result.get("response_time", "N/A")))
                        f.write("Response Size: {} bytes\n".format(result.get("response_size", "N/A")))
                        f.write("Notes: {}\n".format(result.get("notes", "N/A")))
                        f.write("\n")
                        
                        # HTTP Request
                        if "request" in result:
                            f.write("HTTP REQUEST:\n")
                            f.write("-" * 30 + "\n")
                            try:
                                # Write request with proper encoding handling
                                request_text = result["request"]
                                if isinstance(request_text, str):
                                    # Try to write as-is first, fallback to safe encoding if needed
                                    try:
                                        f.write(request_text)
                                    except UnicodeEncodeError:
                                        # If Unicode fails, try UTF-8 encoding
                                        safe_text = request_text.encode('utf-8', errors='replace').decode('utf-8')
                                        f.write(safe_text)
                                else:
                                    f.write(str(request_text))
                            except Exception as e:
                                # Last resort: write raw bytes representation
                                f.write("Raw request data: " + repr(request_text))
                            f.write("\n\n")
                        
                        # HTTP Response
                        if "response" in result:
                            f.write("HTTP RESPONSE:\n")
                            f.write("-" * 30 + "\n")
                            try:
                                # Write response with proper encoding handling
                                response_text = result["response"]
                                if isinstance(response_text, str):
                                    # Try to write as-is first, fallback to safe encoding if needed
                                    try:
                                        f.write(response_text)
                                    except UnicodeEncodeError:
                                        # If Unicode fails, try UTF-8 encoding
                                        safe_text = response_text.encode('utf-8', errors='replace').decode('utf-8')
                                        f.write(safe_text)
                                else:
                                    f.write(str(response_text))
                            except Exception as e:
                                # Last resort: write raw bytes representation
                                f.write("Raw response data: " + repr(response_text))
                            f.write("\n\n")
                        
                        f.write("=" * 80 + "\n\n")
                
                exported_files.append(filename)
            
            # Show success message
            message = "Successfully exported {} unique API paths ({} total requests) to {} files:\n\n".format(total_unique_paths, len(self._bulkResults), total_files)
            for filename in exported_files:
                message += "• {}\n".format(filename)
            message += "\nExport directory: {}".format(export_dir.getAbsolutePath())
            
            JOptionPane.showMessageDialog(self._mainPanel, message,
                "Export Successful", JOptionPane.INFORMATION_MESSAGE)
            
        except Exception as e:
            self._callbacks.printError("Error exporting results: " + str(e))
            JOptionPane.showMessageDialog(self._mainPanel,
                "Error exporting results: " + str(e),
                "Export Error", JOptionPane.ERROR_MESSAGE)
    
    def _updateBulkSummary(self):
        """Update the bulk testing summary with current status"""
        try:
            if not hasattr(self, '_bulkResults') or not self._bulkResults:
                self._bulkSummaryLabel.setText("No results yet")
                return
            
            total = len(self._bulkResults)
            success_count = len([r for r in self._bulkResults if r["status"] == "Success"])
            error_count = len([r for r in self._bulkResults if r["status"] == "Error"])
            
            if hasattr(self, '_bulkTestingPaused') and self._bulkTestingPaused:
                summary = "PAUSED: {} endpoints tested. Success: {}, Errors: {}".format(total, success_count, error_count)
            elif hasattr(self, '_bulkTestingStopped') and self._bulkTestingStopped:
                summary = "STOPPED: {} endpoints tested. Success: {}, Errors: {}".format(total, success_count, error_count)
            else:
                summary = "Testing: {} endpoints tested. Success: {}, Errors: {}".format(total, success_count, error_count)
            
            self._bulkSummaryLabel.setText(summary)
            
        except Exception as e:
            self._callbacks.printError("Error updating summary: " + str(e))
    
    def _updateBulkTestingEndpoints(self):
        """Update the bulk testing endpoints list when endpoints are loaded"""
        try:
            if hasattr(self, '_bulkEndpointListModel') and hasattr(self, 'endpoints'):
                self._bulkEndpointListModel.clear()
                
                for endpoint in self.endpoints:
                    endpoint_text = endpoint["method"] + " " + endpoint["path"]
                    self._bulkEndpointListModel.addElement(endpoint_text)
                
                # Update endpoint count label
                count = len(self.endpoints)
                if count == 0:
                    self._bulkEndpointCountLabel.setText("No endpoints loaded")
                elif count == 1:
                    self._bulkEndpointCountLabel.setText("1 endpoint loaded")
                else:
                    self._bulkEndpointCountLabel.setText(str(count) + " endpoints loaded")
                
        except Exception as e:
            self._callbacks.printError("Error updating bulk testing endpoints: " + str(e))
    
    def _createBulkResultsMouseListener(self):
        """Create mouse listener for bulk results table context menu"""
        class BulkResultsMouseListener(MouseAdapter):
            def __init__(self, extender):
                self.extender = extender
            
            def mousePressed(self, event):
                if event.isPopupTrigger():
                    self._showContextMenu(event)
            
            def mouseReleased(self, event):
                if event.isPopupTrigger():
                    self._showContextMenu(event)
            
            def _showContextMenu(self, event):
                # Get selected row
                row = self.extender._bulkResultsTable.rowAtPoint(event.getPoint())
                if row >= 0:
                    self.extender._bulkResultsTable.setRowSelectionInterval(row, row)
                    
                    # Create context menu
                    popup = JPopupMenu()
                    
                    # Get endpoint details from the selected row
                    method = self.extender._bulkResultsTable.getValueAt(row, 1)
                    path = self.extender._bulkResultsTable.getValueAt(row, 2)
                    
                    # Find the original endpoint
                    endpoint = None
                    for ep in self.extender.endpoints:
                        if ep["method"] == method and ep["path"] == path:
                            endpoint = ep
                            break
                    
                    if endpoint:
                        # Send to Repeater
                        repeaterItem = JMenuItem("Send to Repeater")
                        repeaterItem.addActionListener(lambda e: self.extender._sendEndpointToRepeater(endpoint))
                        popup.add(repeaterItem)
                        
                        # Send to Intruder
                        intruderItem = JMenuItem("Send to Intruder")
                        intruderItem.addActionListener(lambda e: self.extender._sendEndpointToIntruder(endpoint))
                        popup.add(intruderItem)
                        
                        # Send to Scanner
                        scannerItem = JMenuItem("Send to Scanner")
                        scannerItem.addActionListener(lambda e: self.extender._sendEndpointToScanner(endpoint))
                        popup.add(scannerItem)
                        
                        popup.addSeparator()
                        
                        # Copy URL
                        copyUrlItem = JMenuItem("Copy URL")
                        copyUrlItem.addActionListener(lambda e: self.extender._sendEndpointToRepeater(endpoint))
                        popup.add(copyUrlItem)
                        
                        # Copy as curl
                        copyCurlItem = JMenuItem("Copy as curl")
                        copyCurlItem.addActionListener(lambda e: self.extender._sendEndpointToRepeater(endpoint))
                        popup.add(copyCurlItem)
                    
                    # Show popup
                    popup.show(event.getComponent(), event.getX(), event.getY())
        
        return BulkResultsMouseListener(self)
    
    def _createBulkResultsRenderer(self):
        """Create custom renderer for bulk results table to show status colors"""
        from javax.swing.table import DefaultTableCellRenderer
        from java.awt import Color
        
        class BulkResultsRenderer(DefaultTableCellRenderer):
            def __init__(self):
                super(BulkResultsRenderer, self).__init__()
                self.setOpaque(True)
            
            def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
                component = super(BulkResultsRenderer, self).getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column)
                
                if not isSelected:
                    # Get status from first column
                    status = table.getValueAt(row, 0)
                    
                    if status == "Success":
                        component.setBackground(Color(200, 255, 200))  # Light green
                    elif status == "Error":
                        component.setBackground(Color(255, 200, 200))  # Light red
                    elif status == "Timeout":
                        component.setBackground(Color(255, 255, 200))  # Light yellow
                    else:
                        component.setBackground(table.getBackground())
                else:
                    component.setBackground(table.getSelectionBackground())
                
                return component
        
        return BulkResultsRenderer()
    
    def _createBulkEndpointSelectionListener(self):
        """Create list selection listener for bulk testing endpoints list"""
        class BulkEndpointSelectionListener(ListSelectionListener):
            def __init__(self, extender):
                self.extender = extender
            
            def valueChanged(self, event):
                if not event.getValueIsAdjusting():
                    # Get selected endpoint
                    selected_index = self.extender._bulkEndpointList.getSelectedIndex()
                    if selected_index >= 0:
                        endpoint = self.extender._bulkEndpointListModel.getElementAt(selected_index)
                        # You can add endpoint details display here if needed
                        pass
        
        return BulkEndpointSelectionListener(self)
    
    def _sendEndpointToRepeater(self, endpoint):
        """Send a specific endpoint to Repeater"""
        try:
            # Set the current endpoint in the tester tab
            self.current_endpoint = endpoint
            self._loadEndpointDetails()
            
            # Switch to API Tester tab
            self._tabbedPane.setSelectedIndex(1)
            
            # Send to Repeater
            self._sendToRepeater()
            
        except Exception as e:
            self._callbacks.printError("Error sending endpoint to Repeater: " + str(e))
    
    def _sendEndpointToIntruder(self, endpoint):
        """Send a specific endpoint to Intruder"""
        try:
            # Set the current endpoint in the tester tab
            self.current_endpoint = endpoint
            self._tabbedPane.setSelectedIndex(1)
            
            # Send to Intruder
            self._sendToIntruder()
            
        except Exception as e:
            self._callbacks.printError("Error sending endpoint to Intruder: " + str(e))
    
    def _sendEndpointToScanner(self, endpoint):
        """Send a specific endpoint to Scanner"""
        try:
            # Set the current endpoint in the tester tab
            self.current_endpoint = endpoint
            self._loadEndpointDetails()
            
            # Switch to API Tester tab
            self._tabbedPane.setSelectedIndex(1)
            
            # Send to Scanner
            self._sendToScanner()
            
        except Exception as e:
            self._callbacks.printError("Error sending endpoint to Scanner: " + str(e))
    
    def _copyEndpointUrl(self, endpoint):
        """Copy endpoint URL to clipboard"""
        try:
            base_url = self._baseUrlField.getText() if hasattr(self, '_baseUrlField') else ""
            if not base_url:
                base_url = "http://localhost"
            
            full_url = base_url.rstrip('/') + '/' + endpoint["path"].lstrip('/')
            
            from java.awt.datatransfer import StringSelection
            from java.awt import Toolkit
            
            selection = StringSelection(full_url)
            clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
            clipboard.setContents(selection, None)
            
            JOptionPane.showMessageDialog(self._mainPanel,
                "URL copied to clipboard",
                "Success", JOptionPane.INFORMATION_MESSAGE)
                
        except Exception as e:
            self._callbacks.printError("Error copying URL: " + str(e))
    
    def _copyEndpointAsCurl(self, endpoint):
        """Copy endpoint as curl command"""
        try:
            method = endpoint["method"]
            path = endpoint["path"]
            
            # Get base URL
            base_url = self._baseUrlField.getText() if hasattr(self, '_baseUrlField') else ""
            if not base_url:
                base_url = "http://localhost"
            
            full_url = base_url.rstrip('/') + '/' + path.lstrip('/')
            
            # Build curl command
            curl_cmd = "curl"
            
            # Add method
            if method != "GET":
                curl_cmd += " -X " + method
            
            # Add headers
            headers = self._buildEndpointHeaders(endpoint)
            for name, value in headers.items():
                curl_cmd += " -H '" + str(name) + ": " + str(value) + "'"
            
            # Add body
            if method in ["POST", "PUT", "PATCH"]:
                body = self._buildEndpointBody(endpoint)
                if body and body != "{}":
                    # Escape single quotes in body
                    escaped_body = body.replace("'", "'\"'\"'")
                    curl_cmd += " -d '" + escaped_body + "'"
            
            # Add URL
            curl_cmd += " '" + full_url + "'"
            
            # Copy to clipboard
            from java.awt.datatransfer import StringSelection
            from java.awt import Toolkit
            
            selection = StringSelection(curl_cmd)
            clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
            clipboard.setContents(False)
            
            JOptionPane.showMessageDialog(self._mainPanel,
                "curl command copied to clipboard",
                "Success", JOptionPane.INFORMATION_MESSAGE)
            
        except Exception as e:
            self._callbacks.printError("Error copying as curl: " + str(e))
    
    def _buildEndpointHeaders(self, endpoint):
        """Build headers for a specific endpoint"""
        try:
            headers = {}
            details = endpoint.get("details", {})
            parameters = details.get("parameters", [])
            
            # Step 1: Add headers from Swagger spec parameters
            for param in parameters:
                if param.get("in") == "header":
                    name = param.get("name", "")
                    value = param.get("default", "")
                    if name and value:
                        headers[name] = value
            
            # Step 2: Add authentication headers
            if hasattr(self, 'auth_profiles') and self.auth_profiles:
                for profile in self.auth_profiles:
                    if profile.get("enabled", False):
                        auth_type = profile.get("type")
                        if auth_type == "Bearer Token":
                            headers["Authorization"] = "Bearer " + profile.get("value", "")
                        elif auth_type == "Basic Auth":
                            import base64
                            credentials = profile.get("username", "") + ":" + profile.get("password", "")
                            encoded = base64.b64encode(credentials.encode()).decode()
                            headers["Authorization"] = "Basic " + encoded
                        elif auth_type == "Custom Header":
                            headers[profile.get("key", "")] = profile.get("value", "")
            
            # Step 3: Add global custom headers (these can override spec and auth headers)
            if hasattr(self, 'custom_headers'):
                for header in self.custom_headers:
                    if header.get("enabled", False):
                        name = header.get("name", "")
                        value = header.get("value", "")
                        if name and value:
                            headers[name] = value
            
            # Step 4: Apply header overrides (these take final precedence)
            if hasattr(self, 'header_overrides'):
                for override in self.header_overrides:
                    if override and override.get("enabled", False):
                        name = override.get("name", "")
                        value = override.get("value", "")
                        if name and value:
                            headers[name] = value
            
            return headers
        except Exception as e:
            self._callbacks.printError("Error building endpoint headers: " + str(e))
            return {}
    
    def _buildEndpointBody(self, endpoint):
        """Build body for a specific endpoint"""
        try:
            method = endpoint["method"]
            if method not in ["POST", "PUT", "PATCH"]:
                return ""
            
            details = endpoint.get("details", {})
            parameters = details.get("parameters", [])
            
            # Check for body parameter
            for param in parameters:
                if param.get("in") == "body":
                    schema = param.get("schema", {})
                    if schema:
                        return self._generateComprehensiveExample(schema)
            
            # Check for form data
            form_params = []
            for param in parameters:
                if param.get("in") == "formData":
                    name = param.get("name", "")
                    param_type = param.get("type", "string")
                    example = self._generateExample({"type": param_type})
                    form_params.append("{}={}".format(name, example))
            
            if form_params:
                return "&".join(form_params)
            
            return "{}"
        except Exception as e:
            self._callbacks.printError("Error building endpoint body: " + str(e))
            return "{}"
    
    def _createBulkTestingTab(self):
        """Create the bulk testing tab for testing all APIs sequentially"""
        panel = JPanel(BorderLayout())
        
        # Top panel for controls
        topPanel = JPanel()
        topPanel.setBorder(BorderFactory.createTitledBorder("Bulk Testing Controls"))
        layout = GroupLayout(topPanel)
        topPanel.setLayout(layout)
        layout.setAutoCreateGaps(True)
        layout.setAutoCreateContainerGaps(True)
        
        # Components
        self._startBulkButton = JButton("Start Bulk Testing", actionPerformed=self._startBulkTesting)
        self._startBulkButton.setBackground(Color(76, 175, 80))  # Green
        self._startBulkButton.setForeground(Color.WHITE)
        self._startBulkButton.setPreferredSize(Dimension(150, 30))
        self._startBulkButton.setToolTipText("Start testing all endpoints sequentially")
        
        self._pauseBulkButton = JButton("Pause", actionPerformed=self._pauseBulkTesting)
        self._pauseBulkButton.setBackground(Color(255, 152, 0))  # Orange
        self._pauseBulkButton.setForeground(Color.WHITE)
        self._pauseBulkButton.setPreferredSize(Dimension(100, 30))
        self._pauseBulkButton.setEnabled(False)  # Initially disabled
        self._pauseBulkButton.setToolTipText("Pause testing - can be resumed later")
        
        self._resumeBulkButton = JButton("Resume", actionPerformed=self._resumeBulkTesting)
        self._resumeBulkButton.setBackground(Color(33, 150, 243))  # Blue
        self._resumeBulkButton.setForeground(Color.WHITE)
        self._resumeBulkButton.setPreferredSize(Dimension(100, 30))
        self._resumeBulkButton.setEnabled(False)  # Initially disabled
        self._resumeBulkButton.setToolTipText("Resume testing from where it was paused")
        
        self._stopBulkButton = JButton("Stop", actionPerformed=self._stopBulkTesting)
        self._stopBulkButton.setBackground(Color(244, 67, 54))  # Red
        self._stopBulkButton.setForeground(Color.WHITE)
        self._stopBulkButton.setPreferredSize(Dimension(100, 30))
        self._stopBulkButton.setEnabled(False)  # Initially disabled
        self._stopBulkButton.setToolTipText("Stop testing completely - cannot be resumed")
        
        self._restartBulkButton = JButton("Restart", actionPerformed=self._restartBulkTesting)
        self._restartBulkButton.setBackground(Color(156, 39, 176))  # Purple
        self._restartBulkButton.setForeground(Color.WHITE)
        self._restartBulkButton.setPreferredSize(Dimension(100, 30))
        self._restartBulkButton.setToolTipText("Restart testing from the beginning")
        
        clearButton = JButton("Clear Results", actionPerformed=self._clearBulkResults)
        clearButton.setBackground(Color.WHITE)
        clearButton.setForeground(Color.BLACK)
        clearButton.setPreferredSize(Dimension(120, 30))
        clearButton.setToolTipText("Clear all testing results and reset progress")
        
        # Progress panel
        progressPanel = JPanel()
        progressLayout = GroupLayout(progressPanel)
        progressPanel.setLayout(progressLayout)
        progressLayout.setAutoCreateGaps(True)
        progressLayout.setAutoCreateContainerGaps(True)
        
        progressLabel = JLabel("Progress:")
        self._bulkProgressBar = JProgressBar(0, 100)
        self._bulkProgressBar.setStringPainted(True)
        self._bulkProgressBar.setString("Ready")
        
        self._bulkStatusLabel = JLabel("No testing started")
        self._bulkStatusLabel.setForeground(Color(100, 100, 100))
        
        progressLayout.setHorizontalGroup(
            progressLayout.createSequentialGroup()
                .addComponent(progressLabel)
                .addComponent(self._bulkProgressBar)
                .addComponent(self._bulkStatusLabel)
        )
        
        progressLayout.setVerticalGroup(
            progressLayout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                .addComponent(progressLabel)
                .addComponent(self._bulkProgressBar)
                .addComponent(self._bulkStatusLabel)
        )
        
        # Options panel
        optionsPanel = JPanel()
        optionsLayout = GroupLayout(optionsPanel)
        optionsPanel.setLayout(optionsLayout)
        optionsLayout.setAutoCreateGaps(True)
        optionsLayout.setAutoCreateContainerGaps(True)
        
        delayLabel = JLabel("Delay between requests (ms):")
        self._bulkDelayField = JTextField("1000", 10)
        self._bulkDelayField.setToolTipText("Delay between consecutive requests to avoid overwhelming the server")
        
        timeoutLabel = JLabel("Request timeout (ms):")
        self._bulkTimeoutField = JTextField("10000", 10)
        self._bulkTimeoutField.setToolTipText("Timeout for each individual request")
        
        optionsLayout.setHorizontalGroup(
            optionsLayout.createSequentialGroup()
                .addComponent(delayLabel)
                .addComponent(self._bulkDelayField)
                .addComponent(timeoutLabel)
                .addComponent(self._bulkTimeoutField)
        )
        
        optionsLayout.setVerticalGroup(
            optionsLayout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                .addComponent(delayLabel)
                .addComponent(self._bulkDelayField)
                .addComponent(timeoutLabel)
                .addComponent(self._bulkTimeoutField)
        )
        
        # Top panel layout - Use GroupLayout for proper organization
        topLayout = GroupLayout(topPanel)
        topPanel.setLayout(topLayout)
        topLayout.setAutoCreateGaps(True)
        topLayout.setAutoCreateContainerGaps(True)
        
        # Create a button panel for the control buttons
        buttonPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        buttonPanel.add(self._startBulkButton)
        buttonPanel.add(self._pauseBulkButton)
        buttonPanel.add(self._resumeBulkButton)
        buttonPanel.add(self._stopBulkButton)
        buttonPanel.add(self._restartBulkButton)
        buttonPanel.add(clearButton)
        
        # Layout the top panel with proper spacing
        topLayout.setHorizontalGroup(
            topLayout.createSequentialGroup()
                .addComponent(buttonPanel)
                .addComponent(progressPanel)
                .addComponent(optionsPanel)
        )
        
        topLayout.setVerticalGroup(
            topLayout.createSequentialGroup()
                .addComponent(buttonPanel)
                .addComponent(progressPanel)
                .addComponent(optionsPanel)
        )
        
        # Center panel with split pane for endpoints and results
        centerPanel = JPanel(BorderLayout())
        
        # Create split pane for left (endpoints) and right (results)
        splitPane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        
        # Left panel - Endpoints list (similar to API Tester tab)
        leftPanel = JPanel(BorderLayout())
        leftPanel.setBorder(BorderFactory.createTitledBorder("Endpoints to Test"))
        leftPanel.setPreferredSize(Dimension(350, 600))
        
        # Endpoint count label
        self._bulkEndpointCountLabel = JLabel("No endpoints loaded")
        leftPanel.add(self._bulkEndpointCountLabel, BorderLayout.NORTH)
        
        # Endpoints list
        self._bulkEndpointListModel = DefaultListModel()
        self._bulkEndpointList = JList(self._bulkEndpointListModel)
        self._bulkEndpointList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        
        # Add selection listener to show endpoint details
        self._bulkEndpointList.addListSelectionListener(self._createBulkEndpointSelectionListener())
        
        endpointScrollPane = JScrollPane(self._bulkEndpointList)
        leftPanel.add(endpointScrollPane, BorderLayout.CENTER)
        
        # Right panel - Results table
        rightPanel = JPanel(BorderLayout())
        rightPanel.setBorder(BorderFactory.createTitledBorder("Bulk Testing Results"))
        
        # Results table with sorting capability
        columns = ["Status", "Method", "Path", "Response Code", "Response Time", "Size", "Notes"]
        self._bulkResultsTableModel = DefaultTableModel(columns, 0)
        
        # Create sortable table
        self._bulkResultsTable = JTable(self._bulkResultsTableModel)
        
        # Set column widths
        self._bulkResultsTable.getColumnModel().getColumn(0).setPreferredWidth(80)   # Status
        self._bulkResultsTable.getColumnModel().getColumn(1).setPreferredWidth(80)   # Method
        self._bulkResultsTable.getColumnModel().getColumn(2).setPreferredWidth(200)  # Path
        self._bulkResultsTable.getColumnModel().getColumn(3).setPreferredWidth(100)  # Response Code
        self._bulkResultsTable.getColumnModel().getColumn(4).setPreferredWidth(100)  # Response Time
        self._bulkResultsTable.getColumnModel().getColumn(5).setPreferredWidth(80)   # Size
        self._bulkResultsTable.getColumnModel().getColumn(6).setPreferredWidth(150)  # Notes
        
        # Make table non-editable
        from java.lang import Object
        self._bulkResultsTable.setDefaultEditor(Object, None)
        
        # Enable sorting for all columns
        from javax.swing.table import TableRowSorter
        sorter = TableRowSorter(self._bulkResultsTableModel)
        self._bulkResultsTable.setRowSorter(sorter)
        
        # Add right-click context menu
        self._bulkResultsTable.addMouseListener(self._createBulkResultsMouseListener())
        
        # Add custom renderer for status column to show colors
        self._bulkResultsTable.setDefaultRenderer(Object, self._createBulkResultsRenderer())
        
        resultsScrollPane = JScrollPane(self._bulkResultsTable)
        rightPanel.add(resultsScrollPane, BorderLayout.CENTER)
        
        # Add panels to split pane
        splitPane.setLeftComponent(leftPanel)
        splitPane.setRightComponent(rightPanel)
        splitPane.setDividerLocation(350)
        
        centerPanel.add(splitPane, BorderLayout.CENTER)
        
        # Bottom panel for summary and export
        bottomPanel = JPanel(BorderLayout())
        bottomPanel.setBorder(BorderFactory.createTitledBorder("Summary & Export"))
        
        # Summary section
        summaryPanel = JPanel()
        summaryPanel.setLayout(FlowLayout(FlowLayout.LEFT))
        self._bulkSummaryLabel = JLabel("No tests run yet")
        self._bulkSummaryLabel.setForeground(Color(100, 100, 100))
        summaryPanel.add(self._bulkSummaryLabel)
        
        # Export section with filtering options
        exportPanel = JPanel()
        exportPanel.setBorder(BorderFactory.createTitledBorder("Export Results"))
        exportLayout = FlowLayout(FlowLayout.LEFT)
        exportPanel.setLayout(exportLayout)
        
        # Export controls
        chunkLabel = JLabel("Chunk Size:")
        self._exportChunkField = JTextField("25", 5)
        self._exportChunkField.setToolTipText("Number of API requests/responses per export file")
        
        # Export type selection
        exportTypeLabel = JLabel("Export Type:")
        self._exportTypeCombo = JComboBox(["Full Results", "API List Only", "Requests Only", "Responses Only"])
        self._exportTypeCombo.setToolTipText("Choose what to export")
        
        # Status code filter
        statusFilterLabel = JLabel("Status Filter:")
        self._statusFilterField = JTextField("", 15)
        self._statusFilterField.setToolTipText("Filter by status codes (e.g., 200,401,503 or leave empty for all)")
        
        self._exportButton = JButton("Export Results", actionPerformed=self._exportBulkResults)
        self._exportButton.setBackground(Color(76, 175, 80))  # Green
        self._exportButton.setForeground(Color.WHITE)
        self._exportButton.setEnabled(False)  # Initially disabled until results exist
        self._exportButton.setToolTipText("Export HTTP requests and responses to files")
        
        exportPanel.add(chunkLabel)
        exportPanel.add(self._exportChunkField)
        exportPanel.add(exportTypeLabel)
        exportPanel.add(self._exportTypeCombo)
        exportPanel.add(statusFilterLabel)
        exportPanel.add(self._statusFilterField)
        exportPanel.add(self._exportButton)
        
        # Add both panels to bottom panel
        bottomPanel.add(summaryPanel, BorderLayout.NORTH)
        bottomPanel.add(exportPanel, BorderLayout.CENTER)
        
        # Add panels to main panel
        panel.add(topPanel, BorderLayout.NORTH)
        panel.add(centerPanel, BorderLayout.CENTER)
        panel.add(bottomPanel, BorderLayout.SOUTH)
        
        # Initialize bulk testing state
        self._bulkTestingActive = False
        self._bulkTestingPaused = False
        self._bulkTestingStopped = False
        self._bulkCurrentIndex = 0
        self._bulkTestingThread = None
        self._bulkResults = []
        
        # Initialize button states
        self._updateBulkTestingButtonStates()
        
        return panel
        
    # Duplicate method removed - using the complete one below
        
    def _createSettingsTab(self):
        """Create the settings tab"""
        panel = JPanel()
        layout = GroupLayout(panel)
        panel.setLayout(layout)
        layout.setAutoCreateGaps(True)
        layout.setAutoCreateContainerGaps(True)
        
        # Authentication section
        authBorder = BorderFactory.createTitledBorder("Authentication Management")
        authPanel = JPanel(BorderLayout())
        authPanel.setBorder(authBorder)
        
        # Add new authentication section
        addAuthPanel = JPanel()
        addAuthLayout = GroupLayout(addAuthPanel)
        addAuthPanel.setLayout(addAuthLayout)
        addAuthLayout.setAutoCreateGaps(True)
        addAuthLayout.setAutoCreateContainerGaps(True)
        
        # Auth type
        authTypeLabel = JLabel("Auth Type:")
        self._authTypeCombo = JComboBox(["None", "Bearer Token", "API Key", "Basic Auth", "Custom Header"])
        self._authTypeCombo.addActionListener(lambda e: self._updateAuthFields())
        
        # Auth fields
        self._authKeyLabel = JLabel("Key:")
        self._authKeyField = JTextField(20)
        self._authValueLabel = JLabel("Value:")
        self._authValueField = JTextField(30)
        
        # Profile name
        profileLabel = JLabel("Profile Name:")
        self._profileNameField = JTextField(20)
        self._profileNameField.setToolTipText("Give this authentication a name for easy management")
        
        # Add auth button
        addAuthButton = JButton("Add Authentication", actionPerformed=self._addAuthProfile)
        
        # Layout auth panel
        addAuthLayout.setHorizontalGroup(
            addAuthLayout.createParallelGroup()
                .addGroup(addAuthLayout.createSequentialGroup()
                    .addComponent(authTypeLabel)
                    .addComponent(self._authTypeCombo)
                    .addComponent(profileLabel)
                    .addComponent(self._profileNameField))
                .addGroup(addAuthLayout.createSequentialGroup()
                    .addComponent(self._authKeyLabel)
                    .addComponent(self._authKeyField)
                    .addComponent(self._authValueLabel)
                    .addComponent(self._authValueField))
                .addComponent(addAuthButton)
        )
        
        addAuthLayout.setVerticalGroup(
            addAuthLayout.createSequentialGroup()
                .addGroup(addAuthLayout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(authTypeLabel)
                    .addComponent(self._authTypeCombo)
                    .addComponent(profileLabel)
                    .addComponent(self._profileNameField))
                .addGroup(addAuthLayout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(self._authKeyLabel)
                    .addComponent(self._authKeyField)
                    .addComponent(self._authValueLabel)
                    .addComponent(self._authValueField))
                .addComponent(addAuthButton)
        )
        
        # Add the add auth panel to the auth panel
        authPanel.add(addAuthPanel, BorderLayout.NORTH)
        
        # Authentication profiles table
        authTablePanel = JPanel(BorderLayout())
        authTablePanel.setBorder(BorderFactory.createEmptyBorder(10, 0, 0, 0))
        
        # Table for existing auth profiles
        self._authTableModel = DefaultTableModel(["Profile Name", "Type", "Key/Username", "Value/Password", "Actions"], 0)
        self._authTable = JTable(self._authTableModel)
        self._authTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        
        # Set column widths
        self._authTable.getColumnModel().getColumn(0).setPreferredWidth(120)  # Profile Name
        self._authTable.getColumnModel().getColumn(1).setPreferredWidth(80)   # Type
        self._authTable.getColumnModel().getColumn(2).setPreferredWidth(100)  # Key/Username
        self._authTable.getColumnModel().getColumn(3).setPreferredWidth(100)  # Value/Password
        self._authTable.getColumnModel().getColumn(4).setPreferredWidth(150)  # Actions
        
        # Add table to panel
        authTablePanel.add(JScrollPane(self._authTable), BorderLayout.CENTER)
        
        # Auth table buttons
        authButtonPanel = JPanel()
        editAuthButton = JButton("Edit Selected", actionPerformed=self._editAuthProfile)
        deleteAuthButton = JButton("Delete Selected", actionPerformed=self._deleteAuthProfile)
        applySelectedButton = JButton("Apply Selected", actionPerformed=self._applySelectedAuth)
        clearAllButton = JButton("Clear All", actionPerformed=self._clearAllAuth)
        
        authButtonPanel.add(editAuthButton)
        authButtonPanel.add(deleteAuthButton)
        authButtonPanel.add(applySelectedButton)
        authButtonPanel.add(clearAllButton)
        
        # Add save/load buttons
        saveLoadPanel = JPanel()
        saveProfilesButton = JButton("Save Profiles", actionPerformed=self._saveAuthProfiles)
        loadProfilesButton = JButton("Load Profiles", actionPerformed=self._loadAuthProfiles)
        
        saveProfilesButton.setBackground(Color(60, 120, 60))
        saveProfilesButton.setForeground(Color.WHITE)
        loadProfilesButton.setBackground(Color(60, 60, 120))
        loadProfilesButton.setForeground(Color.WHITE)
        
        saveLoadPanel.add(saveProfilesButton)
        saveLoadPanel.add(loadProfilesButton)
        
        authButtonPanel.add(saveLoadPanel)
        
        authTablePanel.add(authButtonPanel, BorderLayout.SOUTH)
        
        # Add the table panel to the auth panel
        authPanel.add(authTablePanel, BorderLayout.CENTER)
        
        # Custom headers section
        headersBorder = BorderFactory.createTitledBorder("Custom Headers (Applied to All Requests)")
        headersPanel = JPanel(BorderLayout())
        headersPanel.setBorder(headersBorder)
        
        # Headers table with better columns
        self._headersTableModel = DefaultTableModel(["Header Name", "Header Value", "Description", "Enabled"], 0)
        self._headersTable = JTable(self._headersTableModel)
        self._headersTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        
        # Add mouse listener for clicking on enabled column
        self._headersTable.addMouseListener(self._createHeadersTableMouseListener())
        
        # Set column widths
        self._headersTable.getColumnModel().getColumn(0).setPreferredWidth(150)  # Header Name
        self._headersTable.getColumnModel().getColumn(1).setPreferredWidth(200)  # Header Value
        self._headersTable.getColumnModel().getColumn(2).setPreferredWidth(120)  # Description
        self._headersTable.getColumnModel().getColumn(3).setPreferredWidth(80)   # Enabled
        
        # Add table to panel
        headersPanel.add(JScrollPane(self._headersTable), BorderLayout.CENTER)
        
        # Enhanced headers buttons
        headerButtonPanel = JPanel()
        addHeaderButton = JButton("Add Header", actionPerformed=self._addHeader)
        editHeaderButton = JButton("Edit Selected", actionPerformed=self._editHeader)
        removeHeaderButton = JButton("Remove Selected", actionPerformed=self._removeHeader)
        clearAllHeadersButton = JButton("Clear All", actionPerformed=self._clearAllHeaders)
        
        # Style buttons
        addHeaderButton.setBackground(Color(60, 120, 60))
        addHeaderButton.setForeground(Color.WHITE)
        editHeaderButton.setBackground(Color(60, 60, 120))
        editHeaderButton.setForeground(Color.WHITE)
        removeHeaderButton.setBackground(Color(120, 60, 60))
        removeHeaderButton.setForeground(Color.WHITE)
        clearAllHeadersButton.setBackground(Color(80, 80, 80))
        clearAllHeadersButton.setForeground(Color.WHITE)
        
        headerButtonPanel.add(addHeaderButton)
        headerButtonPanel.add(editHeaderButton)
        headerButtonPanel.add(removeHeaderButton)
        headerButtonPanel.add(clearAllHeadersButton)
        
        # Add save/load buttons for headers
        headerSaveLoadPanel = JPanel()
        saveHeadersButton = JButton("Save Headers", actionPerformed=self._saveHeaders)
        loadHeadersButton = JButton("Load Headers", actionPerformed=self._loadHeaders)
        
        saveHeadersButton.setBackground(Color(60, 120, 60))
        saveHeadersButton.setForeground(Color.WHITE)
        loadHeadersButton.setBackground(Color(60, 60, 120))
        loadHeadersButton.setForeground(Color.WHITE)
        
        headerSaveLoadPanel.add(saveHeadersButton)
        headerSaveLoadPanel.add(loadHeadersButton)
        
        # Combine button panels
        headerControlsPanel = JPanel(BorderLayout())
        headerControlsPanel.add(headerButtonPanel, BorderLayout.NORTH)
        headerControlsPanel.add(headerSaveLoadPanel, BorderLayout.SOUTH)
        
        headersPanel.add(headerControlsPanel, BorderLayout.SOUTH)
        
        # Header overrides section (globally override specific header values)
        overridesBorder = BorderFactory.createTitledBorder("Global Header Overrides (Update existing headers by name)")
        overridesPanel = JPanel(BorderLayout())
        overridesPanel.setBorder(overridesBorder)
        
        # Table for overrides
        self._headerOverridesTableModel = DefaultTableModel(["Header Name", "New Value", "Enabled"], 0)
        self._headerOverridesTable = JTable(self._headerOverridesTableModel)
        overridesPanel.add(JScrollPane(self._headerOverridesTable), BorderLayout.CENTER)
        
        # Buttons for overrides
        overridesBtnPanel = JPanel()
        addOverrideBtn = JButton("Add Override", actionPerformed=self._addHeaderOverride)
        editOverrideBtn = JButton("Edit Selected", actionPerformed=self._editHeaderOverride)
        removeOverrideBtn = JButton("Remove Selected", actionPerformed=self._removeHeaderOverride)
        applyOverrideBtn = JButton("Apply to Current Request", actionPerformed=self._applyHeaderOverrides)
        
        overridesBtnPanel.add(addOverrideBtn)
        overridesBtnPanel.add(editOverrideBtn)
        overridesBtnPanel.add(removeOverrideBtn)
        overridesBtnPanel.add(applyOverrideBtn)
        overridesPanel.add(overridesBtnPanel, BorderLayout.SOUTH)
        
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
                .addComponent(overridesPanel)
                .addComponent(optionsPanel)
        )
        
        layout.setVerticalGroup(
            layout.createSequentialGroup()
                .addComponent(authPanel)
                .addComponent(headersPanel)
                .addComponent(overridesPanel)
                .addComponent(optionsPanel)
        )
        
        return JScrollPane(panel)
    
    def _createTesterTab(self):
        """Create the main API tester tab"""
        # Create main panel
        mainPanel = JPanel(BorderLayout())
        
        # Create split pane for left and right panels
        splitPane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        
        # Left panel - Endpoint list
        leftPanel = JPanel(BorderLayout())
        leftPanel.setBorder(BorderFactory.createTitledBorder("Endpoints"))
        leftPanel.setPreferredSize(Dimension(300, 600))
        
        # Endpoint count label
        self._endpointCountLabel = JLabel("No endpoints loaded")
        leftPanel.add(self._endpointCountLabel, BorderLayout.NORTH)
        
        # Search panel
        searchPanel = JPanel(BorderLayout())
        searchPanel.setBorder(BorderFactory.createEmptyBorder(5, 0, 5, 0))
        
        # Search label
        searchLabel = JLabel("Search:")
        searchLabel.setForeground(Color(200, 200, 200))
        searchPanel.add(searchLabel, BorderLayout.WEST)
        
        # Search field with history
        self._searchField = JTextField(20)
        self._searchField.setToolTipText("Type to search endpoints by method, path, or description")
        self._searchField.getDocument().addDocumentListener(self._createSearchDocumentListener())
        
        # Add key listener for Enter key to select first result
        self._searchField.addKeyListener(self._createSearchKeyListener())
        
        # Search history button
        historyButton = JButton("⌄", actionPerformed=self._showSearchHistory)
        historyButton.setToolTipText("Show search history")
        historyButton.setPreferredSize(Dimension(25, 25))
        historyButton.setBackground(Color(80, 80, 80))
        historyButton.setForeground(Color(200, 200, 200))
        
        searchPanel.add(self._searchField, BorderLayout.CENTER)
        searchPanel.add(historyButton, BorderLayout.EAST)
        
        # Clear search button (moved to options panel)
        clearSearchButton = JButton("Clear", actionPerformed=self._clearSearch)
        clearSearchButton.setToolTipText("Clear all filters and search")
        clearSearchButton.setPreferredSize(Dimension(60, 20))
        clearSearchButton.setBackground(Color(80, 80, 80))
        clearSearchButton.setForeground(Color(200, 200, 200))
        
        # Search options panel
        searchOptionsPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        searchOptionsPanel.setBorder(BorderFactory.createEmptyBorder(2, 0, 0, 0))
        
        # Method filter
        methodFilterLabel = JLabel("Method:")
        methodFilterLabel.setForeground(Color(180, 180, 180))
        methodFilterLabel.setFont(Font("Dialog", Font.PLAIN, 10))
        
        self._methodFilterCombo = JComboBox(["All", "GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
        self._methodFilterCombo.setPreferredSize(Dimension(80, 20))
        self._methodFilterCombo.addActionListener(lambda e: self._applyFilters())
        
        # Tag filter
        tagFilterLabel = JLabel("Tag:")
        tagFilterLabel.setForeground(Color(180, 180, 180))
        tagFilterLabel.setFont(Font("Dialog", Font.PLAIN, 10))
        
        self._tagFilterCombo = JComboBox(["All"])
        self._tagFilterCombo.setPreferredSize(Dimension(100, 20))
        self._tagFilterCombo.addActionListener(lambda e: self._applyFilters())
        
        # Search scope filter
        scopeLabel = JLabel("Search in:")
        scopeLabel.setForeground(Color(180, 180, 180))
        scopeLabel.setFont(Font("Dialog", Font.PLAIN, 10))
        
        self._searchScopeCombo = JComboBox(["All", "Method", "Path", "Description", "Tags"])
        self._searchScopeCombo.setPreferredSize(Dimension(100, 20))
        self._searchScopeCombo.addActionListener(lambda e: self._applyFilters())
        
        searchOptionsPanel.add(methodFilterLabel)
        searchOptionsPanel.add(self._methodFilterCombo)
        searchOptionsPanel.add(tagFilterLabel)
        searchOptionsPanel.add(self._tagFilterCombo)
        searchOptionsPanel.add(scopeLabel)
        searchOptionsPanel.add(self._searchScopeCombo)
        searchOptionsPanel.add(clearSearchButton)
        
        # Search statistics label
        self._searchStatsLabel = JLabel("")
        self._searchStatsLabel.setForeground(Color(150, 150, 150))
        self._searchStatsLabel.setFont(Font("Dialog", Font.PLAIN, 9))
        self._searchStatsLabel.setBorder(BorderFactory.createEmptyBorder(2, 5, 0, 0))
        searchOptionsPanel.add(self._searchStatsLabel)
        
        # Add search options below the search field
        searchContainerPanel = JPanel(BorderLayout())
        searchContainerPanel.add(searchPanel, BorderLayout.NORTH)
        searchContainerPanel.add(searchOptionsPanel, BorderLayout.CENTER)
        
        # Endpoint list
        self._endpointListModel = DefaultListModel()
        self._endpointList = JList(self._endpointListModel)
        self._endpointList.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)
        self._endpointList.addListSelectionListener(self._createListSelectionListener())
        
        # Add keyboard shortcut for sending requests (Ctrl+Space / Cmd+Space)
        self._endpointList.addKeyListener(self._createRequestShortcutListener())
        
        # Add context menu for endpoint list
        self._endpointList.addMouseListener(self._createEndpointListMouseListener())
        
        # Info panel with debug buttons and endpoint management
        infoPanel = JPanel(BorderLayout())
        
        # Left side - Debug and test buttons
        leftButtonsPanel = JPanel()
        leftButtonsPanel.setLayout(FlowLayout(FlowLayout.LEFT))
        
        # Debug button
        debugButton = JButton("Debug List", actionPerformed=self._debugEndpointList)
        debugButton.setToolTipText("Debug endpoint list contents")
        debugButton.setBackground(Color(60, 60, 60))  # Dark button background
        debugButton.setForeground(Color(200, 200, 200))  # Light button text
        
        # Add test buttons for debugging
        testEndpointButton = JButton("Add Test Endpoint", actionPerformed=self._addTestEndpoint)
        testEndpointButton.setToolTipText("Add a test endpoint to verify list functionality")
        testEndpointButton.setBackground(Color(60, 60, 60))  # Dark button background
        testEndpointButton.setForeground(Color(200, 200, 200))  # Light button text
        
        testComprehensiveButton = JButton("Test Comprehensive", actionPerformed=self._testCurrentEndpointComprehensive)
        testComprehensiveButton.setToolTipText("Test comprehensive example generation for current endpoint")
        testComprehensiveButton.setBackground(Color(60, 60, 60))  # Dark button background
        testComprehensiveButton.setForeground(Color(200, 200, 200))  # Light button text
        
        leftButtonsPanel.add(debugButton)
        leftButtonsPanel.add(testEndpointButton)
        leftButtonsPanel.add(testComprehensiveButton)
        
        # Right side - Endpoint management buttons
        rightButtonsPanel = JPanel()
        rightButtonsPanel.setLayout(FlowLayout(FlowLayout.RIGHT))
        
        # Remove selected endpoint button
        removeSelectedButton = JButton("Remove Selected", actionPerformed=self._removeSelectedEndpoint)
        removeSelectedButton.setToolTipText("Remove the currently selected endpoint from the list")
        removeSelectedButton.setBackground(Color(200, 100, 100))  # Red background for removal
        removeSelectedButton.setForeground(Color(255, 255, 255))  # White text
        
        # Remove multiple endpoints button
        removeMultipleButton = JButton("Remove Multiple", actionPerformed=self._removeMultipleEndpoints)
        removeMultipleButton.setToolTipText("Remove multiple selected endpoints from the list")
        removeMultipleButton.setBackground(Color(200, 100, 100))  # Red background for removal
        removeMultipleButton.setForeground(Color(255, 255, 255))  # White text
        
        # Clear all endpoints button
        clearAllButton = JButton("Clear All", actionPerformed=self._clearAllEndpoints)
        clearAllButton.setToolTipText("Remove all endpoints from the list")
        clearAllButton.setBackground(Color(200, 100, 100))  # Red background for removal
        clearAllButton.setForeground(Color(255, 255, 255))  # White text
        
        rightButtonsPanel.add(removeSelectedButton)
        rightButtonsPanel.add(removeMultipleButton)
        rightButtonsPanel.add(clearAllButton)
        
        # Add both panels to info panel
        infoPanel.add(leftButtonsPanel, BorderLayout.WEST)
        infoPanel.add(rightButtonsPanel, BorderLayout.EAST)
        
        # Add search panel and endpoint list to a container panel
        listContainerPanel = JPanel(BorderLayout())
        listContainerPanel.add(searchContainerPanel, BorderLayout.NORTH)
        listContainerPanel.add(JScrollPane(self._endpointList), BorderLayout.CENTER)
        
        leftPanel.add(listContainerPanel, BorderLayout.CENTER)
        leftPanel.add(infoPanel, BorderLayout.SOUTH)
        
        # Debug: Log the creation of the endpoint list
        self._callbacks.printOutput("Created endpoint list with model size: " + str(self._endpointListModel.getSize()))
        self._callbacks.printOutput("Endpoint list visible: " + str(self._endpointList.isVisible()))
        self._callbacks.printOutput("Endpoint list enabled: " + str(self._endpointList.isEnabled()))
        
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
        self._sendButton.setToolTipText("Send Request (Shortcut: Ctrl+Space)")
        
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
        
        # Request body editor (only for methods that support bodies)
        self._bodyPanel = JPanel(BorderLayout())
        self._bodyPanel.setBorder(BorderFactory.createTitledBorder("Request Body"))
        
        # Request editor with syntax highlighting
        self._requestEditor = JTextPane()
        self._requestEditor.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._requestEditor.setBackground(Color(40, 40, 40))
        self._requestEditor.setForeground(Color(200, 200, 200))
        
        # Create and attach right-click popup for sending to Repeater/Intruder/etc.
        self._createRequestPopupMenu()
        self._requestEditor.addMouseListener(RequestMouseListener(self))
        
        # Also add right-click popup to the request URL field and control panel
        self._requestUrlField.addMouseListener(RequestMouseListener(self))
        controlPanel.addMouseListener(RequestMouseListener(self))
        
        # Formatting buttons
        formatPanel = JPanel()
        prettyButton = JButton("Pretty Print", actionPerformed=self._prettyPrintRequest)
        minifyButton = JButton("Minify", actionPerformed=self._minifyRequest)
        highlightButton = JButton("Highlight", actionPerformed=self._highlightRequest)
        themeButton = JButton("Burp Theme", actionPerformed=self._toggleTheme)
        
        formatPanel.add(prettyButton)
        formatPanel.add(minifyButton)
        formatPanel.add(highlightButton)
        formatPanel.add(themeButton)
        
        self._bodyPanel.add(formatPanel, BorderLayout.NORTH)
        self._bodyPanel.add(JScrollPane(self._requestEditor), BorderLayout.CENTER)
        
        # Initially hide body panel for GET requests
        self._updateBodyPanelVisibility()
        
        # Add method change listener to show/hide body panel
        self._methodCombo.addActionListener(lambda e: self._validateMethodChange())
        
        requestPanel.add(self._bodyPanel, BorderLayout.CENTER)
        
        # Add right-click popup to the main request panel and body panel
        requestPanel.addMouseListener(RequestMouseListener(self))
        self._bodyPanel.addMouseListener(RequestMouseListener(self))
        
        # Add keyboard shortcut for sending requests (Ctrl+Space / Cmd+Space)
        self._requestEditor.addKeyListener(self._createRequestShortcutListener())
        self._requestUrlField.addKeyListener(self._createRequestShortcutListener())
        
        # Also add Swing key bindings as backup (more reliable)
        self._addSwingKeyBindings()
        
        # Response panel
        responsePanel = JPanel(BorderLayout())
        responsePanel.setBorder(BorderFactory.createTitledBorder("Response"))
        
        # Response info label and controls
        responseInfoPanel = JPanel(BorderLayout())
        
        # Response info label (status, length, time)
        self._responseInfoLabel = JLabel("No response yet")
        self._responseInfoLabel.setForeground(Color(200, 200, 200))
        self._responseInfoLabel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5))
        responseInfoPanel.add(self._responseInfoLabel, BorderLayout.WEST)
        
        # Response control buttons
        responseButtonPanel = JPanel()
        clearResponseButton = JButton("Clear Response", actionPerformed=self._clearResponse)
        clearResponseButton.setBackground(Color(60, 60, 60))
        clearResponseButton.setForeground(Color(200, 200, 200))
        
        # Debug button to show endpoint parameters
        debugParamsButton = JButton("Show Params", actionPerformed=self._showEndpointParameters)
        debugParamsButton.setBackground(Color(80, 80, 80))
        debugParamsButton.setForeground(Color(200, 200, 200))
        debugParamsButton.setToolTipText("Show current endpoint parameters for debugging")
        
        # Test keyboard shortcut button
        testShortcutButton = JButton("Test Shortcut", actionPerformed=self._testKeyboardShortcut)
        testShortcutButton.setBackground(Color(100, 100, 80))
        testShortcutButton.setForeground(Color(200, 200, 200))
        testShortcutButton.setToolTipText("Test if keyboard shortcut system is working")
        
        responseButtonPanel.add(clearResponseButton)
        responseButtonPanel.add(debugParamsButton)
        responseButtonPanel.add(testShortcutButton)
        responseInfoPanel.add(responseButtonPanel, BorderLayout.EAST)
        
        responsePanel.add(responseInfoPanel, BorderLayout.NORTH)
        
        # Response editor with syntax highlighting
        self._responseEditor = JTextPane()
        self._responseEditor.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._responseEditor.setBackground(Color(40, 40, 40))
        self._responseEditor.setForeground(Color(200, 200, 200))
        self._responseEditor.setEditable(False)
        self._responseEditor.setText("Send a request to see the response here...\n\n" +
                                   "The response will appear here with syntax highlighting.\n" +
                                   "Status, response time, and content length will be shown above.")
        
        # Style the response editor
        responseScrollPane = JScrollPane(self._responseEditor)
        responseScrollPane.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5))
        responsePanel.add(responseScrollPane, BorderLayout.CENTER)
        
        # Add panels to request tabbed pane
        requestTabbedPane.addTab("Request", requestPanel)
        requestTabbedPane.addTab("Parameters", self._createParametersPanel())
        requestTabbedPane.addTab("Headers", self._createRequestHeadersPanel())
        
        # Create a split pane for request and response (like Burp Repeater)
        requestResponseSplitPane = JSplitPane(JSplitPane.VERTICAL_SPLIT, requestTabbedPane, responsePanel)
        requestResponseSplitPane.setDividerLocation(400)  # Give more space to request initially
        requestResponseSplitPane.setResizeWeight(0.6)  # Request gets 60% of space
        
        # Set minimum sizes to ensure both panels are always visible
        requestTabbedPane.setMinimumSize(Dimension(300, 200))
        responsePanel.setMinimumSize(Dimension(300, 150))
        
        rightPanel.add(requestResponseSplitPane, BorderLayout.CENTER)
        
        # Set up split pane
        splitPane.setLeftComponent(leftPanel)
        splitPane.setRightComponent(rightPanel)
        splitPane.setDividerLocation(300)
        
        mainPanel.add(splitPane, BorderLayout.CENTER)
        
        return mainPanel
    
    def _clearResponse(self, event):
        """Clear the response panel"""
        self._responseEditor.setText("Response cleared")
        self._responseInfoLabel.setText("No response yet")
        self._responseInfoLabel.setForeground(Color(200, 200, 200))
    
    def _showEndpointParameters(self, event):
        """Show debug info about current endpoint parameters"""
        if not self.current_endpoint:
            JOptionPane.showMessageDialog(self._mainPanel, "No endpoint selected", "Info", JOptionPane.INFORMATION_MESSAGE)
            return
            
        details = self.current_endpoint["details"]
        method = self.current_endpoint["method"]
        path = self.current_endpoint["path"]
        
        # Get parameters
        parameters = details.get("parameters", [])
        path_parameters = self.current_endpoint.get("path_parameters", [])
        
        # Check for body parameters
        body_params = [p for p in parameters if p.get("in") == "body"]
        
        info = "Endpoint: " + method + " " + path + "\n\n"
        info += "Method-level parameters: " + str(len(parameters)) + "\n"
        info += "Path-level parameters: " + str(len(path_parameters)) + "\n"
        info += "Body parameters: " + str(len(body_params)) + "\n\n"
        
        if body_params:
            info += "Body parameters found:\n"
            for param in body_params:
                info += "- " + param.get("name", "unnamed") + " (" + param.get("type", "unknown") + ")\n"
        else:
            info += "No body parameters defined for this method.\n"
            info += "Body panel should be hidden.\n"
        
        JOptionPane.showMessageDialog(self._mainPanel, info, "Endpoint Parameters", JOptionPane.INFORMATION_MESSAGE)
    
    def _createSearchDocumentListener(self):
        """Create a document listener for the search field"""
        class SearchDocumentListener(DocumentListener):
            def __init__(self, extender):
                self.extender = extender
            
            def insertUpdate(self, event):
                self.extender._performSearch()
            
            def removeUpdate(self, event):
                self.extender._performSearch()
            
            def changedUpdate(self, event):
                self.extender._performSearch()
        
        return SearchDocumentListener(self)
    
    def _createSearchKeyListener(self):
        """Create a key listener for the search field"""
        class SearchKeyListener(KeyAdapter):
            def __init__(self, extender):
                self.extender = extender
            
            def keyPressed(self, event):
                if event.getKeyCode() == KeyEvent.VK_ENTER:
                    # Select first result when Enter is pressed
                    if self.extender._endpointListModel.getSize() > 0:
                        self.extender._endpointList.setSelectedIndex(0)
                        self.extender._endpointList.requestFocus()
                elif event.getKeyCode() == KeyEvent.VK_ESCAPE:
                    # Clear search when Escape is pressed
                    self.extender._clearSearch(None)
                elif event.getKeyCode() == KeyEvent.VK_DOWN:
                    # Move focus to endpoint list when Down arrow is pressed
                    self.extender._endpointList.requestFocus()
                    if self.extender._endpointListModel.getSize() > 0:
                        self.extender._endpointList.setSelectedIndex(0)
        
        return SearchKeyListener(self)
    
    def _showSearchHistory(self, event):
        """Show search history dropdown"""
        if not hasattr(self, '_searchHistory') or not self._searchHistory:
            JOptionPane.showMessageDialog(self._mainPanel, "No search history yet", "Search History", JOptionPane.INFORMATION_MESSAGE)
            return
        
        # Create history popup menu
        popup = JPopupMenu()
        
        for search_term in self._searchHistory[-10:]:  # Show last 10 searches
            menu_item = JMenuItem(search_term)
            menu_item.addActionListener(lambda e, term=search_term: self._loadSearchFromHistory(term))
            popup.add(menu_item)
        
        # Show popup below the history button
        button = event.getSource()
        popup.show(button, 0, button.getHeight())
    
    def _loadSearchFromHistory(self, search_term):
        """Load a search term from history"""
        self._searchField.setText(search_term)
        self._performSearch()
    
    def _addToSearchHistory(self, search_term):
        """Add search term to history"""
        if not hasattr(self, '_searchHistory'):
            self._searchHistory = []
        
        # Remove if already exists
        if search_term in self._searchHistory:
            self._searchHistory.remove(search_term)
        
        # Add to front
        self._searchHistory.insert(0, search_term)
        
        # Keep only last 20 searches
        if len(self._searchHistory) > 20:
            self._searchHistory = self._searchHistory[:20]
    
    def _performSearch(self):
        """Perform search on endpoints"""
        search_term = self._searchField.getText().strip()
        
        # Add to search history if not empty
        if search_term:
            self._addToSearchHistory(search_term)
        
        # Apply both search term and filters
        self._applyFilters()
    
    def _applyFilters(self):
        """Apply search term and filters to endpoints"""
        search_term = self._searchField.getText().strip().lower()
        selected_method = str(self._methodFilterCombo.getSelectedItem())
        selected_tag = str(self._tagFilterCombo.getSelectedItem())
        
        # Filter endpoints based on search term and filters
        filtered_endpoints = []
        for endpoint in self.endpoints:
            # Check method filter
            if selected_method != "All" and endpoint["method"] != selected_method:
                continue
            
            # Check tag filter
            if selected_tag != "All":
                endpoint_tags = endpoint.get("tags", [])
                if selected_tag not in endpoint_tags:
                    continue
            
            # Check search term
            if search_term:
                selected_scope = str(self._searchScopeCombo.getSelectedItem())
                found = False
                
                if selected_scope == "All" or selected_scope == "Method":
                    if search_term in endpoint["method"].lower():
                        found = True
                
                if selected_scope == "All" or selected_scope == "Path":
                    if search_term in endpoint["path"].lower():
                        found = True
                
                if selected_scope == "All" or selected_scope == "Description":
                    description = endpoint.get("description", "").lower()
                    if search_term in description:
                        found = True
                
                if selected_scope == "All" or selected_scope == "Tags":
                    tags = " ".join(endpoint.get("tags", [])).lower()
                    if search_term in tags:
                        found = True
                
                if not found:
                    continue
            
            filtered_endpoints.append(endpoint)
        
        # Update the list with filtered results
        self._updateEndpointList(filtered_endpoints)
        
        # Update count label and search statistics
        if filtered_endpoints:
            if search_term or selected_method != "All" or selected_tag != "All":
                self._endpointCountLabel.setText(str(len(filtered_endpoints)) + " of " + str(len(self.endpoints)) + " endpoints")
                
                # Show search statistics
                stats_text = ""
                if search_term:
                    stats_text += "Search: '" + search_term + "' "
                if selected_method != "All":
                    stats_text += "Method: " + selected_method + " "
                if selected_tag != "All":
                    stats_text += "Tag: " + selected_tag + " "
                
                if hasattr(self, '_searchStatsLabel'):
                    self._searchStatsLabel.setText(stats_text)
            else:
                self._endpointCountLabel.setText(str(len(filtered_endpoints)) + " endpoints loaded")
                if hasattr(self, '_searchStatsLabel'):
                    self._searchStatsLabel.setText("")
        else:
            self._endpointCountLabel.setText("No endpoints match the current filters")
            if hasattr(self, '_searchStatsLabel'):
                self._searchStatsLabel.setText("No results")
    
    def _showAllEndpoints(self):
        """Show all endpoints (clear search)"""
        self._updateEndpointList(self.endpoints)
        self._updateEndpointCountLabel()
    
    def _updateEndpointList(self, endpoints_to_show):
        """Update the endpoint list with filtered results"""
        self._endpointListModel.clear()
        
        # Store the filtered endpoints for selection
        self._filtered_endpoints = endpoints_to_show
        
        for endpoint in endpoints_to_show:
            endpoint_text = endpoint["method"] + " " + endpoint["path"]
            self._endpointListModel.addElement(endpoint_text)
        
        # Force UI update
        self._endpointList.revalidate()
        self._endpointList.repaint()
    
    def _clearSearch(self, event):
        """Clear the search field and show all endpoints"""
        self._searchField.setText("")
        self._methodFilterCombo.setSelectedItem("All")
        self._tagFilterCombo.setSelectedItem("All")
        self._searchScopeCombo.setSelectedItem("All")
        self._showAllEndpoints()
    
    def _validateMethodChange(self):
        """Validate method change and update UI accordingly"""
        if not self.current_endpoint:
            return
            
        new_method = str(self._methodCombo.getSelectedItem())
        current_method = self.current_endpoint["method"]
        
        if new_method != current_method:
            self._callbacks.printOutput("Method changed from " + current_method + " to " + new_method)
            self._callbacks.printOutput("WARNING: Method changed but endpoint details are for " + current_method)
            self._callbacks.printOutput("Body panel visibility may be incorrect - endpoint parameters don't match method")
            
            # Show warning to user
            JOptionPane.showMessageDialog(self._mainPanel, 
                "Method changed to " + new_method + " but endpoint details are for " + current_method + ".\n" +
                "Body panel visibility may be incorrect.\n\n" +
                "Please select the endpoint again to get correct parameters for " + new_method + ".",
                "Method Mismatch Warning", 
                JOptionPane.WARNING_MESSAGE)
        
        # Update body panel visibility
        self._updateBodyPanelVisibility()
    
    def _updateBodyPanelVisibility(self):
        """Show/hide request body panel based on current method and its actual parameters"""
        method = str(self._methodCombo.getSelectedItem())
        
        # First check if the current method actually has body parameters
        has_body_param = False
        if self.current_endpoint:
            details = self.current_endpoint["details"]
            parameters = details.get("parameters", [])
            
            # Check if this specific method has a body parameter
            for param in parameters:
                if param.get("in") == "body":
                    has_body_param = True
                    self._callbacks.printOutput("Method " + method + " has body parameter: " + param.get("name", "unnamed"))
                    break
        
        # Methods that support request bodies AND have body parameters
        body_supporting_methods = ["POST", "PUT", "PATCH", "DELETE"]
        
        if method in body_supporting_methods and has_body_param:
            self._bodyPanel.setVisible(True)
            self._requestEditor.setEnabled(True)
            self._bodyPanel.setBorder(BorderFactory.createTitledBorder("Request Body"))
            self._callbacks.printOutput("Showing body panel for " + method + " (has body parameter)")
        else:
            # Hide body panel - either method doesn't support bodies or has no body parameter
            self._bodyPanel.setVisible(False)
            self._requestEditor.setEnabled(False)
            if method not in body_supporting_methods:
                self._callbacks.printOutput("Hiding body panel for " + method + " (method doesn't support bodies)")
            else:
                self._callbacks.printOutput("Hiding body panel for " + method + " (no body parameter defined)")
    
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
        """Parse Swagger/OpenAPI specification or Postman Collection"""
        try:
            # Try parsing as JSON first
            try:
                parsed_content = json.loads(content)
                self._callbacks.printOutput("Successfully parsed as JSON")
            except Exception as e:
                self._callbacks.printOutput("JSON parsing failed: " + str(e))
                # Try parsing as YAML
                if yaml:
                    try:
                        parsed_content = yaml.safe_load(content)
                        self._callbacks.printOutput("Successfully parsed as YAML")
                    except Exception as e:
                        raise Exception("Failed to parse as JSON or YAML: " + str(e))
                else:
                    raise Exception("Failed to parse as JSON and YAML support is not available")
            
            # Check if it's a Postman Collection
            if self._isPostmanCollection(parsed_content):
                self._callbacks.printOutput("Detected Postman Collection format")
                self.swagger_spec = self._convertPostmanToSwagger(parsed_content)
                self._callbacks.printOutput("Converted Postman Collection to Swagger format")
            else:
                self._callbacks.printOutput("Detected Swagger/OpenAPI format")
                self.swagger_spec = parsed_content
            
            # Extract base URL
            self.base_url = self._extractBaseUrl(source_url)
            
            # Debug: Show what we parsed
            self._callbacks.printOutput("Parsed spec keys: " + str(self.swagger_spec.keys()))
            if "paths" in self.swagger_spec:
                self._callbacks.printOutput("Paths found: " + str(list(self.swagger_spec["paths"].keys())))
            
            # Update spec info
            self._updateSpecInfo()
            
            # Parse endpoints
            self._parseEndpoints()
            
            # Update progress bar
            self._progressBar.setIndeterminate(False)
            self._progressBar.setString("Successfully loaded " + str(len(self.endpoints)) + " endpoints")
            
            # Update base URL field if it exists
            if hasattr(self, '_baseUrlField'):
                self._baseUrlField.setText(self.base_url)
                self._callbacks.printOutput("Updated base URL field: " + self.base_url)
            
            # Force UI updates
            self._callbacks.printOutput("Specification loaded successfully. Forcing UI updates...")
            
            # Force the endpoint list to update
            if hasattr(self, '_endpointList'):
                self._endpointList.revalidate()
                self._endpointList.repaint()
                self._callbacks.printOutput("Forced endpoint list UI update")
            
            # Force the endpoints table to update
            if hasattr(self, '_endpointsTable'):
                self._endpointsTable.revalidate()
                self._endpointsTable.repaint()
                self._callbacks.printOutput("Forced endpoints table UI update")
            
            # Force bulk testing tab updates
            if hasattr(self, '_bulkEndpointListModel'):
                self._updateBulkTestingEndpoints()
                self._callbacks.printOutput("Updated bulk testing endpoints")
            
            # Show success message
            JOptionPane.showMessageDialog(self._mainPanel,
                "Successfully loaded " + str(len(self.endpoints)) + " endpoints from " + source_url,
                "Load Successful", JOptionPane.INFORMATION_MESSAGE)
            
        except Exception as e:
            self._progressBar.setIndeterminate(False)
            self._progressBar.setString("Parse error: " + str(e))
            self._callbacks.printError("Error parsing specification: " + str(e))
            JOptionPane.showMessageDialog(self._mainPanel,
                "Error parsing specification: " + str(e), 
                "Error", JOptionPane.ERROR_MESSAGE)
    
    def _isPostmanCollection(self, parsed_content):
        """Check if the parsed content is a Postman Collection"""
        try:
            # Check for Postman Collection v2.1.0 signature
            if "info" in parsed_content and "item" in parsed_content:
                info = parsed_content["info"]
                if "schema" in info and "postman" in info["schema"].lower():
                    return True
                # Also check for Postman Collection v2.0
                if "_postman_id" in info:
                    return True
            return False
        except:
            return False
    
    def _convertPostmanToSwagger(self, postman_content):
        """Convert Postman Collection to Swagger format"""
        try:
            # Create basic Swagger structure
            swagger_spec = {
                "swagger": "2.0",
                "info": {
                    "title": postman_content.get("info", {}).get("name", "Postman Collection"),
                    "version": "1.0.0",
                    "description": postman_content.get("info", {}).get("description", "Converted from Postman Collection")
                },
                "paths": {},
                "host": "{{baseUrl}}",  # Postman uses variable
                "basePath": "",
                "schemes": ["https", "http"]
            }
            
            # Extract endpoints from Postman items
            self._extractPostmanEndpoints(postman_content.get("item", []), swagger_spec["paths"])
            
            self._callbacks.printOutput("Converted Postman Collection with " + str(len(swagger_spec["paths"])) + " paths")
            return swagger_spec
            
        except Exception as e:
            self._callbacks.printError("Error converting Postman Collection: " + str(e))
            raise Exception("Failed to convert Postman Collection: " + str(e))
    
    def _extractPostmanEndpoints(self, items, paths_dict, parent_path=""):
        """Recursively extract endpoints from Postman Collection items"""
        try:
            for item in items:
                if not isinstance(item, dict):
                    continue
                
                item_name = item.get("name", "")
                item_type = item.get("item", None)
                
                if item_type:
                    # This is a folder, recurse with updated path
                    current_path = parent_path + "/" + item_name if parent_path else "/" + item_name
                    self._extractPostmanEndpoints(item_type, paths_dict, current_path)
                else:
                    # This is an endpoint
                    request = item.get("request", {})
                    if request:
                        method = request.get("method", "GET").upper()
                        url_info = request.get("url", {})
                        
                        if url_info:
                            # Extract path from URL
                            raw_url = url_info.get("raw", "")
                            if raw_url and "{{baseUrl}}" in raw_url:
                                # Extract path part after baseUrl
                                path_part = raw_url.split("{{baseUrl}}")[-1]
                                if "?" in path_part:
                                    path_part = path_part.split("?")[0]  # Remove query params
                                
                                # Use only the path from the URL, not combined with parent path
                                # This prevents duplication of path segments
                                full_path = path_part
                                
                                # Clean up path (remove double slashes, etc.)
                                full_path = "/" + "/".join(filter(None, full_path.split("/")))
                                
                                # Create endpoint entry
                                if full_path not in paths_dict:
                                    paths_dict[full_path] = {}
                                
                                # Extract parameters
                                parameters = []
                                
                                # Query parameters
                                if "query" in url_info:
                                    for query_param in url_info["query"]:
                                        if isinstance(query_param, dict):
                                            param_name = query_param.get("key", "")
                                            param_value = query_param.get("value", "")
                                            param_desc = query_param.get("description", "")
                                            if param_name:
                                                parameters.append({
                                                    "name": param_name,
                                                    "in": "query",
                                                    "type": "string",
                                                    "required": param_desc and "required" in param_desc.lower(),
                                                    "description": param_desc
                                                })
                                
                                # Path parameters (extract from path)
                                path_params = re.findall(r'\{([^}]+)\}', full_path)
                                for param_name in path_params:
                                    parameters.append({
                                        "name": param_name,
                                        "in": "path",
                                        "type": "string",
                                        "required": True,
                                        "description": "Path parameter: " + param_name
                                    })
                                
                                # Headers
                                headers = request.get("header", [])
                                for header in headers:
                                    if isinstance(header, dict):
                                        header_name = header.get("key", "")
                                        header_value = header.get("value", "")
                                        header_desc = header.get("description", "")
                                        if header_name and header_name.lower() not in ["content-type", "accept"]:
                                            parameters.append({
                                                "name": header_name,
                                                "in": "header",
                                                "type": "string",
                                                "required": header_desc and "required" in header_desc.lower(),
                                                "description": header_desc
                                            })
                                
                                # Body parameters
                                body = request.get("body", {})
                                if body and body.get("mode") == "raw":
                                    raw_body = body.get("raw", "")
                                    if raw_body:
                                        try:
                                            # Try to parse as JSON to determine if it's a body parameter
                                            json.loads(raw_body)
                                            parameters.append({
                                                "name": "body",
                                                "in": "body",
                                                "required": True,
                                                "description": "Request body",
                                                "schema": {"type": "object"}
                                            })
                                        except:
                                            # Not valid JSON, might be form data
                                            pass
                                
                                # Create the endpoint
                                paths_dict[full_path][method.lower()] = {
                                    "summary": item_name,
                                    "description": item_name,
                                    "parameters": parameters,
                                    "tags": [parent_path.split("/")[-1] if parent_path else "root"],
                                    "responses": {
                                        "200": {
                                            "description": "Success"
                                        }
                                    }
                                }
                                
                                self._callbacks.printOutput("Added Postman endpoint: " + method + " " + full_path)
            
        except Exception as e:
            self._callbacks.printError("Error extracting Postman endpoints: " + str(e))
            
    def _extractBaseUrl(self, source_url):
        """Extract base URL from source URL and swagger spec"""
        parsed = urlparse(source_url)
        base = parsed.scheme + "://" + parsed.netloc
        self._callbacks.printOutput("Source URL base: " + base)
        
        # Check for servers in OpenAPI 3.0
        if self.swagger_spec and "servers" in self.swagger_spec:
            servers = self.swagger_spec["servers"]
            if servers and len(servers) > 0:
                server_url = servers[0].get("url", "")
                self._callbacks.printOutput("Found OpenAPI 3.0 server: " + server_url)
                if server_url.startswith("http"):
                    return server_url
                elif server_url.startswith("/"):
                    return base + server_url
                    
        # Check for host/basePath in Swagger 2.0
        if self.swagger_spec:
            host = self.swagger_spec.get("host", "")
            base_path = self.swagger_spec.get("basePath", "")
            schemes = self.swagger_spec.get("schemes", ["https"])
            
            self._callbacks.printOutput("Swagger 2.0 - host: " + host + ", basePath: " + base_path + ", schemes: " + str(schemes))
            
            if host:
                scheme = schemes[0] if schemes else "https"
                final_url = scheme + "://" + host + base_path
                self._callbacks.printOutput("Extracted base URL: " + final_url)
                return final_url
                
        self._callbacks.printOutput("Using source URL base: " + base)
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
        
        # Tags
        if "tags" in self.swagger_spec:
            tags = [tag.get("name", "") for tag in self.swagger_spec["tags"]]
            info.append("Tags: " + ", ".join(tags))
        
        # Global consumes/produces
        if "consumes" in self.swagger_spec:
            info.append("Global Consumes: " + ", ".join(self.swagger_spec["consumes"]))
        if "produces" in self.swagger_spec:
            info.append("Global Produces: " + ", ".join(self.swagger_spec["produces"]))
        
        # Definitions count
        if "definitions" in self.swagger_spec:
            info.append("Definitions: " + str(len(self.swagger_spec["definitions"])) + " schemas")
            
        self._specInfoArea.setText("\n".join(info))
        
    def _parseEndpoints(self):
        """Parse endpoints from swagger spec"""
        try:
            self.endpoints = []
            self._endpointsTableModel.setRowCount(0)
            self._endpointListModel.clear()
            
            self._callbacks.printOutput("Starting endpoint parsing...")
            
            if not self.swagger_spec or "paths" not in self.swagger_spec:
                self._callbacks.printOutput("No swagger spec or paths found")
                return
                
            paths = self.swagger_spec["paths"]
            self._callbacks.printOutput("Found " + str(len(paths)) + " paths in swagger spec")
            
            # Debug: Show first few paths
            path_keys = list(paths.keys())
            self._callbacks.printOutput("First 5 paths: " + str(path_keys[:5]))
            
            for path, methods in paths.items():
                self._callbacks.printOutput("Processing path: " + str(path))
                if not isinstance(methods, dict):
                    self._callbacks.printOutput("Path methods is not a dict: " + str(type(methods)) + " - Value: " + str(methods))
                    continue
                
                # Check for path-level parameters
                path_parameters = methods.get("parameters", [])
                if path_parameters:
                    self._callbacks.printOutput("Found " + str(len(path_parameters)) + " path-level parameters for path: " + path)
                
                # Debug: Show methods for this path
                method_keys = list(methods.keys())
                self._callbacks.printOutput("Methods for path " + path + ": " + str(method_keys))
                    
                for method, details in methods.items():
                    self._callbacks.printOutput("Processing method: " + str(method))
                    if method.upper() not in ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]:
                        self._callbacks.printOutput("Skipping non-HTTP method: " + str(method))
                        continue
                        
                    endpoint = {
                        "path": path,
                        "method": method.upper(),
                        "details": details,
                        "path_parameters": path_parameters,  # Store path-level parameters
                        "description": details.get("summary", details.get("description", "")),
                        "tags": details.get("tags", [])  # Store endpoint tags
                    }
                    
                    self.endpoints.append(endpoint)
                    
                    # Add to table
                    tags_text = ", ".join(endpoint["tags"]) if endpoint["tags"] else ""
                    self._endpointsTableModel.addRow([
                        endpoint["method"],
                        endpoint["path"],
                        tags_text,
                        endpoint["description"][:100]
                    ])
                    
                    # Add to list
                    endpoint_text = endpoint["method"] + " " + endpoint["path"]
                    self._endpointListModel.addElement(endpoint_text)
                    # Debug output
                    self._callbacks.printOutput("Added endpoint to list: " + endpoint_text)
            
            # Update endpoint count label
            self._updateEndpointCountLabel()
            
            # Force UI updates
            self._callbacks.printOutput("Parsing complete. Endpoints: " + str(len(self.endpoints)) + ", List size: " + str(self._endpointListModel.getSize()))
            
            # Force the list to repaint
            if hasattr(self, '_endpointList'):
                self._endpointList.revalidate()
                self._endpointList.repaint()
                self._callbacks.printOutput("Forced endpoint list repaint")
            
            # Initialize filtered endpoints to show all endpoints
            self._filtered_endpoints = self.endpoints
            
            # Populate tag filter
            self._populateTagFilter()
            
            # Update bulk testing endpoints list
            self._updateBulkTestingEndpoints()
            
            # Force bulk testing tab to refresh
            if hasattr(self, '_bulkEndpointList'):
                self._bulkEndpointList.revalidate()
                self._bulkEndpointList.repaint()
                self._callbacks.printOutput("Forced bulk testing tab refresh")
            
        except Exception as e:
            self._callbacks.printError("Error parsing endpoints: " + str(e))
            import traceback
            self._callbacks.printError("Traceback: " + str(traceback.format_exc()))
            JOptionPane.showMessageDialog(self._mainPanel,
                "Error parsing endpoints: " + str(e), 
                "Parse Error", JOptionPane.ERROR_MESSAGE)
    
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
    
    def _addTestEndpoint(self, event):
        """Add a test endpoint to verify list functionality"""
        try:
            # Create a test endpoint
            test_endpoint = {
                "path": "/test/endpoint",
                "method": "GET",
                "details": {
                    "summary": "Test endpoint for debugging",
                    "parameters": []
                },
                "description": "Test endpoint for debugging"
            }
            
            # Add to endpoints array
            self.endpoints.append(test_endpoint)
            
            # Add to table
            self._endpointsTableModel.addRow([
                test_endpoint["method"],
                test_endpoint["path"],
                test_endpoint["description"][:100]
            ])
            
            # Add to list
            endpoint_text = test_endpoint["method"] + " " + test_endpoint["path"]
            self._endpointListModel.addElement(endpoint_text)
            
            # Update count label
            self._updateEndpointCountLabel()
            
            # Force UI updates
            self._endpointList.revalidate()
            self._endpointList.repaint()
            
            self._callbacks.printOutput("Added test endpoint: " + endpoint_text)
            JOptionPane.showMessageDialog(self._mainPanel,
                "Test endpoint added successfully!",
                "Success", JOptionPane.INFORMATION_MESSAGE)
                
        except Exception as e:
            JOptionPane.showMessageDialog(self._mainPanel,
                "Error adding test endpoint: " + str(e),
                "Error", JOptionPane.ERROR_MESSAGE)
    
    def _removeSelectedEndpoint(self, event):
        """Remove the currently selected endpoint from the list"""
        try:
            selected_indices = self._endpointList.getSelectedIndices()
            if len(selected_indices) == 0:
                JOptionPane.showMessageDialog(self._mainPanel,
                    "Please select an endpoint to remove.",
                    "No Selection", JOptionPane.WARNING_MESSAGE)
                return
            
            if len(selected_indices) == 1:
                # Single endpoint removal
                index = selected_indices[0]
                endpoint_text = self._endpointListModel.getElementAt(index)
                
                result = JOptionPane.showConfirmDialog(self._mainPanel,
                    "Remove endpoint: {} ?".format(endpoint_text),
                    "Confirm Removal", JOptionPane.YES_NO_OPTION)
                
                if result == JOptionPane.YES_OPTION:
                    # Remove from endpoints array
                    if index < len(self.endpoints):
                        removed_endpoint = self.endpoints.pop(index)
                        self._callbacks.printOutput("Removed endpoint: " + str(removed_endpoint))
                    
                    # Remove from list model
                    self._endpointListModel.remove(index)
                    
                    # Remove from table model
                    if hasattr(self, '_endpointsTableModel') and index < self._endpointsTableModel.getRowCount():
                        self._endpointsTableModel.removeRow(index)
                    
                    # Update count label
                    self._updateEndpointCountLabel()
                    
                    # Update bulk testing endpoints list
                    self._updateBulkTestingEndpoints()
                    
                    # Clear selection
                    self._endpointList.clearSelection()
                    
                    JOptionPane.showMessageDialog(self._mainPanel,
                        "Endpoint removed successfully!",
                        "Success", JOptionPane.INFORMATION_MESSAGE)
            else:
                # Multiple endpoints selected - use the multiple removal method
                self._removeMultipleEndpoints(event)
                
        except Exception as e:
            JOptionPane.showMessageDialog(self._mainPanel,
                "Error removing endpoint: " + str(e),
                "Error", JOptionPane.ERROR_MESSAGE)
    
    def _removeMultipleEndpoints(self, event):
        """Remove multiple selected endpoints from the list"""
        try:
            selected_indices = self._endpointList.getSelectedIndices()
            if len(selected_indices) == 0:
                JOptionPane.showMessageDialog(self._mainPanel,
                    "Please select endpoints to remove.",
                    "No Selection", JOptionPane.WARNING_MESSAGE)
                return
            
            # Sort indices in descending order to avoid index shifting issues
            selected_indices = sorted(selected_indices, reverse=True)
            
            # Confirm removal
            count = len(selected_indices)
            result = JOptionPane.showConfirmDialog(self._mainPanel,
                "Remove {} selected endpoint(s)?\n\nThis action cannot be undone.".format(count),
                "Confirm Multiple Removal", JOptionPane.YES_NO_OPTION)
            
            if result == JOptionPane.YES_OPTION:
                removed_count = 0
                
                # Remove from endpoints array (in reverse order)
                for index in selected_indices:
                    if index < len(self.endpoints):
                        removed_endpoint = self.endpoints.pop(index)
                        self._callbacks.printOutput("Removed endpoint: " + str(removed_endpoint))
                        removed_count += 1
                
                # Remove from list model (in reverse order)
                for index in selected_indices:
                    if index < self._endpointListModel.getSize():
                        self._endpointListModel.remove(index)
                
                # Remove from table model (in reverse order)
                if hasattr(self, '_endpointsTableModel'):
                    for index in selected_indices:
                        if index < self._endpointsTableModel.getRowCount():
                            self._endpointsTableModel.removeRow(index)
                
                                    # Update count label
                    self._updateEndpointCountLabel()
                    
                    # Update bulk testing endpoints list
                    self._updateBulkTestingEndpoints()
                    
                    # Clear selection
                    self._endpointList.clearSelection()
                    
                    JOptionPane.showMessageDialog(self._mainPanel,
                        "Successfully removed {} endpoint(s)!".format(removed_count),
                        "Success", JOptionPane.INFORMATION_MESSAGE)
                
        except Exception as e:
            JOptionPane.showMessageDialog(self._mainPanel,
                "Error removing endpoints: " + str(e),
                "Error", JOptionPane.ERROR_MESSAGE)
    
    def _clearAllEndpoints(self, event):
        """Remove all endpoints from the list"""
        try:
            if not hasattr(self, 'endpoints') or len(self.endpoints) == 0:
                JOptionPane.showMessageDialog(self._mainPanel,
                    "No endpoints to clear.",
                    "No Endpoints", JOptionPane.INFORMATION_MESSAGE)
                return
            
            count = len(self.endpoints)
            result = JOptionPane.showConfirmDialog(self._mainPanel,
                "Clear all {} endpoints?\n\nThis action cannot be undone.".format(count),
                "Confirm Clear All", JOptionPane.YES_NO_OPTION)
            
            if result == JOptionPane.YES_OPTION:
                # Clear endpoints array
                self.endpoints = []
                
                # Clear list model
                self._endpointListModel.clear()
                
                # Clear table model
                if hasattr(self, '_endpointsTableModel'):
                    self._endpointsTableModel.setRowCount(0)
                
                # Update count label
                self._updateEndpointCountLabel()
                
                # Update bulk testing endpoints list
                self._updateBulkTestingEndpoints()
                
                # Clear any current request/response
                if hasattr(self, '_requestEditor'):
                    self._requestEditor.setText("")
                if hasattr(self, '_responseEditor'):
                    self._responseEditor.setText("")
                
                self._callbacks.printOutput("Cleared all {} endpoints".format(count))
                JOptionPane.showMessageDialog(self._mainPanel,
                    "All endpoints cleared successfully!",
                    "Success", JOptionPane.INFORMATION_MESSAGE)
                
        except Exception as e:
            JOptionPane.showMessageDialog(self._mainPanel,
                "Error clearing endpoints: " + str(e),
                "Error", JOptionPane.ERROR_MESSAGE)
    
    def _updateEndpointCountLabel(self):
        """Update the endpoint count label"""
        if hasattr(self, '_endpointCountLabel'):
            count = len(self.endpoints) if hasattr(self, 'endpoints') else 0
            if count == 0:
                self._endpointCountLabel.setText("No endpoints loaded")
            elif count == 1:
                self._endpointCountLabel.setText("1 endpoint loaded")
            else:
                self._endpointCountLabel.setText(str(count) + " endpoints loaded")
    
    def _loadFromFile(self, event):
        """Load Swagger spec from file"""
        chooser = JFileChooser()
        chooser.setDialogTitle("Select Swagger/OpenAPI file")
        
        # Add file filter for JSON and YAML files
        from javax.swing.filechooser import FileNameExtensionFilter
        jsonFilter = FileNameExtensionFilter("JSON files (*.json)", "json")
        yamlFilter = FileNameExtensionFilter("YAML files (*.yaml, *.yml)", "yaml", "yml")
        chooser.addChoosableFileFilter(jsonFilter)
        chooser.addChoosableFileFilter(yamlFilter)
        chooser.setFileFilter(jsonFilter)  # Set JSON as default filter
        
        if chooser.showOpenDialog(self._mainPanel) == JFileChooser.APPROVE_OPTION:
            file = chooser.getSelectedFile()
            try:
                # Validate file extension
                file_path = file.getAbsolutePath()
                if not (file_path.lower().endswith('.json') or file_path.lower().endswith('.yaml') or file_path.lower().endswith('.yml')):
                    JOptionPane.showMessageDialog(self._mainPanel,
                        "Please select a valid Swagger/OpenAPI file (.json, .yaml, or .yml)",
                        "Invalid File Type", JOptionPane.WARNING_MESSAGE)
                    return
                
                with open(file_path, 'r') as f:
                    content = f.read()
                
                self._callbacks.printOutput("Loading file: " + file_path)
                self._parseSwaggerSpec(content, "file://" + file_path)
                
            except Exception as e:
                JOptionPane.showMessageDialog(self._mainPanel,
                    "Error loading file: " + str(e), 
                    "Error", JOptionPane.ERROR_MESSAGE)
    
    def _testParser(self, event):
        """Test the parser with the test Swagger file"""
        try:
            # Try to load the test file
            test_file_path = "test_swagger.json"
            if os.path.exists(test_file_path):
                with open(test_file_path, 'r') as f:
                    content = f.read()
                
                self._callbacks.printOutput("Testing parser with test_swagger.json...")
                self._parseSwaggerSpec(content, "file://" + os.path.abspath(test_file_path))
                
                # Test comprehensive example generation for a specific endpoint
                self._testComprehensiveExample()
                
                JOptionPane.showMessageDialog(self._mainPanel,
                    "Test completed! Check the console for debug output.",
                    "Test Complete", JOptionPane.INFORMATION_MESSAGE)
            else:
                JOptionPane.showMessageDialog(self._mainPanel,
                    "Test file 'test_swagger.json' not found in the extension directory.",
                    "Test File Not Found", JOptionPane.WARNING_MESSAGE)
                    
        except Exception as e:
            JOptionPane.showMessageDialog(self._mainPanel,
                "Test failed: " + str(e), 
                "Test Error", JOptionPane.ERROR_MESSAGE)
    
    def _testComprehensiveExample(self):
        """Test comprehensive example generation for a specific endpoint"""
        try:
            # Find an endpoint with a body parameter
            for endpoint in self.endpoints:
                if endpoint["method"] in ["POST", "PUT", "PATCH"]:
                    details = endpoint["details"]
                    parameters = details.get("parameters", [])
                    
                    for param in parameters:
                        if param.get("in") == "body" and "schema" in param:
                            self._callbacks.printOutput("Testing comprehensive example for: " + endpoint["method"] + " " + endpoint["path"])
                            
                            # Generate comprehensive example
                            comprehensive_example = self._generateComprehensiveExample(param["schema"])
                            basic_example = self._generateExample(param["schema"])
                            
                            self._callbacks.printOutput("Basic example properties: " + str(len(basic_example)) if isinstance(basic_example, dict) else "Basic example: " + str(type(basic_example)))
                            self._callbacks.printOutput("Comprehensive example properties: " + str(len(comprehensive_example)) if isinstance(comprehensive_example, dict) else "Comprehensive example: " + str(type(comprehensive_example)))
                            
                            if isinstance(comprehensive_example, dict):
                                self._callbacks.printOutput("Comprehensive example keys: " + ", ".join(comprehensive_example.keys()))
                            
                            # Only test the first one
                            return
                            
        except Exception as e:
            self._callbacks.printOutput("Error testing comprehensive example: " + str(e))
    
    def _testCurrentEndpointComprehensive(self, event):
        """Test comprehensive example generation for the currently selected endpoint"""
        try:
            if not hasattr(self, 'current_endpoint') or not self.current_endpoint:
                JOptionPane.showMessageDialog(self._mainPanel,
                    "No endpoint selected. Please select an endpoint first.",
                    "No Endpoint Selected", JOptionPane.WARNING_MESSAGE)
                return
            
            endpoint = self.current_endpoint
            self._callbacks.printOutput("Testing comprehensive example for: " + endpoint["method"] + " " + endpoint["path"])
            
            details = endpoint["details"]
            parameters = details.get("parameters", [])
            
            # Find body parameter
            body_param = None
            for param in parameters:
                if param.get("in") == "body" and "schema" in param:
                    body_param = param
                    break
            
            if not body_param:
                JOptionPane.showMessageDialog(self._mainPanel,
                    "No body parameter found for this endpoint.",
                    "No Body Parameter", JOptionPane.INFORMATION_MESSAGE)
                return
            
            # Generate both examples
            basic_example = self._generateExample(body_param["schema"])
            comprehensive_example = self._generateComprehensiveExample(body_param["schema"])
            
            # Show results
            basic_props = len(basic_example) if isinstance(basic_example, dict) else "N/A"
            comprehensive_props = len(comprehensive_example) if isinstance(comprehensive_example, dict) else "N/A"
            
            result_msg = "Endpoint: " + endpoint["method"] + " " + endpoint["path"] + "\n\n"
            result_msg += "Basic example properties: " + str(basic_props) + "\n"
            result_msg += "Comprehensive example properties: " + str(comprehensive_props) + "\n\n"
            
            if isinstance(comprehensive_example, dict):
                result_msg += "Comprehensive example keys:\n"
                result_msg += ", ".join(comprehensive_example.keys())
                
                # Show first few values
                result_msg += "\n\nSample values:\n"
                count = 0
                for key, value in comprehensive_example.items():
                    if count >= 5:  # Limit to first 5
                        break
                    result_msg += key + ": " + str(value)[:50] + "\n"
                    count += 1
                
                if len(comprehensive_example) > 5:
                    result_msg += "... and " + str(len(comprehensive_example) - 5) + " more properties"
            
            JOptionPane.showMessageDialog(self._mainPanel,
                result_msg,
                "Comprehensive Example Test", JOptionPane.INFORMATION_MESSAGE)
                
        except Exception as e:
            JOptionPane.showMessageDialog(self._mainPanel,
                "Error testing comprehensive example: " + str(e),
                "Error", JOptionPane.ERROR_MESSAGE)
                    
    def _createListSelectionListener(self):
        """Create a list selection listener for the endpoint list"""
        class EndpointListSelectionListener(ListSelectionListener):
            def __init__(self, extender):
                self.extender = extender
            
            def valueChanged(self, event):
                if not event.getValueIsAdjusting():
                    self.extender._selectEndpoint()
        
        return EndpointListSelectionListener(self)
    
    def _selectEndpoint(self):
        """Handle endpoint selection"""
        selected = self._endpointList.getSelectedIndex()
        
        # Use filtered endpoints if available, otherwise use all endpoints
        endpoints_to_use = getattr(self, '_filtered_endpoints', self.endpoints)
        
        if selected >= 0 and selected < len(endpoints_to_use):
            self.current_endpoint = endpoints_to_use[selected]
            self._loadEndpointDetails()
        else:
            self._callbacks.printOutput("Invalid selection index: " + str(selected) + " (max: " + str(len(endpoints_to_use) - 1) + ")")
            
    def _loadEndpointDetails(self):
        """Load selected endpoint details into request editor"""
        if not self.current_endpoint:
            return
            
        # Set method
        self._methodCombo.setSelectedItem(self.current_endpoint["method"])
        
        # Get endpoint details
        path = self.current_endpoint["path"]
        details = self.current_endpoint["details"]
        
        # Get path-level parameters (Swagger 2.0)
        path_parameters = self.current_endpoint.get("path_parameters", [])
        if path_parameters:
            self._callbacks.printOutput("Found " + str(len(path_parameters)) + " path-level parameters from stored endpoint")
        
        # Get method-level parameters
        method_parameters = details.get("parameters", [])
        self._callbacks.printOutput("Found " + str(len(method_parameters)) + " method-level parameters")
        
        # Merge parameters (method-level override path-level)
        # Create a map to handle duplicates - method-level takes precedence
        param_map = {}
        
        # Add path parameters first
        for param in path_parameters:
            param_name = param.get("name", "")
            if param_name:
                param_map[param_name] = param
                self._callbacks.printOutput("Added path parameter: " + param_name)
        
        # Override with method parameters
        for param in method_parameters:
            param_name = param.get("name", "")
            if param_name:
                param_map[param_name] = param
                self._callbacks.printOutput("Added method parameter: " + param_name)
        
        all_parameters = param_map.values()
        self._callbacks.printOutput("Total merged parameters: " + str(len(all_parameters)))
        
        # Clear parameter tables
        self._pathParamsTableModel.setRowCount(0)
        self._queryParamsTableModel.setRowCount(0)
        self._headerParamsTableModel.setRowCount(0)
        self._requestHeadersTableModel.setRowCount(0)
        
        # Parse parameters from the spec
        self._parseEndpointParameters(all_parameters, details)
        
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
        
        # Update body panel visibility based on this endpoint's actual parameters
        self._updateBodyPanelVisibility()
    
    def _populateTagFilter(self):
        """Populate the tag filter with available tags"""
        if not hasattr(self, '_tagFilterCombo'):
            return
            
        # Collect all unique tags
        all_tags = set()
        for endpoint in self.endpoints:
            tags = endpoint.get("tags", [])
            all_tags.update(tags)
        
        # Update tag filter combo
        self._tagFilterCombo.removeAllItems()
        self._tagFilterCombo.addItem("All")
        
        # Add tags in alphabetical order
        for tag in sorted(all_tags):
            self._tagFilterCombo.addItem(tag)
        
        self._callbacks.printOutput("Populated tag filter with " + str(len(all_tags)) + " tags")
    
    def _parseEndpointParameters(self, parameters, details):
        """Parse parameters from endpoint definition"""
        self._callbacks.printOutput("Parsing " + str(len(parameters)) + " parameters")
        
        for param in parameters:
            name = param.get("name", "")
            param_type = param.get("type", "string")
            required = param.get("required", False)
            description = param.get("description", "")
            param_in = param.get("in", "")
            
            self._callbacks.printOutput("Processing parameter: " + name + " (in: " + param_in + ", type: " + param_type + ")")
            
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
                self._callbacks.printOutput("Added path parameter to table: " + name)
            elif param_in == "query":
                self._queryParamsTableModel.addRow([name, example_value, param_type, str(required), description])
                self._callbacks.printOutput("Added query parameter to table: " + name)
            elif param_in == "header":
                self._headerParamsTableModel.addRow([name, example_value, param_type, str(required), description])
                self._callbacks.printOutput("Added header parameter to table: " + name)
        
        # Also check for additional headers in the endpoint definition
        if "responses" in details:
            self._callbacks.printOutput("Found responses section with " + str(len(details["responses"])) + " response codes")
            for response_code, response_data in details["responses"].items():
                self._callbacks.printOutput("Processing response code: " + str(response_code))
                if "headers" in response_data:
                    self._callbacks.printOutput("Found " + str(len(response_data["headers"])) + " response headers")
                    for header_name, header_data in response_data["headers"].items():
                        # These are response headers, but useful to know about
                        # Add them to the header params table for reference
                        header_type = "response_header"
                        header_desc = "Response header: " + str(response_data.get("description", ""))
                        self._headerParamsTableModel.addRow([header_name, "", header_type, "false", header_desc])
                        self._callbacks.printOutput("Added response header: " + header_name)
        
        # Check for non-standard responsesObject (some Swagger specs have this)
        if "responsesObject" in details:
            self._callbacks.printOutput("Found non-standard responsesObject with " + str(len(details["responsesObject"])) + " response codes")
            for response_code, response_data in details["responsesObject"].items():
                self._callbacks.printOutput("Processing responsesObject code: " + str(response_code))
                if "headers" in response_data:
                    self._callbacks.printOutput("Found " + str(len(response_data["headers"])) + " responsesObject headers")
                    for header_name, header_data in response_data["headers"].items():
                        # Add these headers as well
                        header_type = "response_header"
                        header_desc = "Response header (responsesObject): " + str(response_data.get("description", ""))
                        self._headerParamsTableModel.addRow([header_name, "", header_type, "false", header_desc])
                        self._callbacks.printOutput("Added responsesObject header: " + header_name)
    
    def _extractParametersFromResponses(self, details):
        """Extract additional parameters from response schemas for comprehensive coverage"""
        additional_params = []
        
        if "responses" in details:
            for response_code, response_data in details["responses"].items():
                if response_code.startswith("2"):  # Success responses
                    # Extract from schema
                    if "schema" in response_data:
                        schema_params = self._extractParametersFromSchema(response_data["schema"])
                        additional_params.extend(schema_params)
                    
                    # Extract from responseSchema (non-standard field)
                    if "responseSchema" in response_data:
                        schema_params = self._extractParametersFromSchema(response_data["responseSchema"])
                        additional_params.extend(schema_params)
        
        # Also check responsesObject
        if "responsesObject" in details:
            for response_code, response_data in details["responsesObject"].items():
                if response_code.startswith("2"):  # Success responses
                    if "schema" in response_data:
                        schema_params = self._extractParametersFromSchema(response_data["schema"])
                        additional_params.extend(schema_params)
                    
                    if "responseSchema" in response_data:
                        schema_params = self._extractParametersFromSchema(response_data["responseSchema"])
                        additional_params.extend(schema_params)
        
        return additional_params
    
    def _extractParametersFromSchema(self, schema):
        """Extract parameters from a schema definition"""
        params = []
        
        if "$ref" in schema:
            resolved_schema = self._resolveSchemaReference(schema["$ref"])
            if resolved_schema:
                return self._extractParametersFromSchema(resolved_schema)
            return params
        
        if schema.get("type") == "object" and "properties" in schema:
            properties = schema["properties"]
            required = schema.get("required", [])
            
            for prop_name, prop_schema in properties.items():
                param = {
                    "name": prop_name,
                    "type": prop_schema.get("type", "string"),
                    "required": prop_name in required,
                    "description": prop_schema.get("description", ""),
                    "in": "body",  # These are body parameters
                    "schema": prop_schema
                }
                params.append(param)
        
        return params
    
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
        """Build comprehensive example request body from endpoint details"""
        if "requestBody" not in details:
            # Check for body parameters (Swagger 2.0)
            parameters = details.get("parameters", [])
            for param in parameters:
                if param.get("in") == "body" and "schema" in param:
                    self._callbacks.printOutput("Building request body from Swagger 2.0 body parameter: " + param.get("name", "unnamed"))
                    return self._schemaToExample(param["schema"])
            
            # If no body parameter found, try to build from response schema (for testing purposes)
            if "responses" in details:
                for response_code, response_data in details["responses"].items():
                    if response_code.startswith("2"):  # Success responses
                        if "schema" in response_data:
                            self._callbacks.printOutput("Building request body from response schema for testing")
                            return self._schemaToExample(response_data["schema"])
                        elif "responseSchema" in response_data:
                            self._callbacks.printOutput("Building request body from responseSchema for testing")
                            return self._schemaToExample(response_data["responseSchema"])
            
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
            # Use the comprehensive example generator for better coverage
            example = self._generateComprehensiveExample(schema)
            return json.dumps(example, indent=2)
        except Exception as e:
            self._callbacks.printOutput("Error in _schemaToExample: " + str(e))
            # Fallback to basic example generator
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
    
    def _resolveSchemaReference(self, ref_path):
        """Resolve schema references with full path support"""
        if not ref_path.startswith("#/"):
            return None
            
        try:
            # Split the reference path
            path_parts = ref_path.split("/")[1:]  # Remove the # and split
            current = self.swagger_spec
            
            # Navigate through the path
            for part in path_parts:
                if isinstance(current, dict) and part in current:
                    current = current[part]
                else:
                    return None
            
            return current
        except Exception as e:
            self._callbacks.printOutput("Error resolving schema reference " + ref_path + ": " + str(e))
            return None
        
    def _generateComprehensiveExample(self, schema, depth=0):
        """Generate comprehensive example from schema with enhanced type handling and full reference resolution"""
        # Prevent infinite recursion
        if depth > 10:
            return "max_depth_exceeded"
        
        if "example" in schema:
            return schema["example"]
        
        # Handle references with full resolution
        if "$ref" in schema and self.swagger_spec:
            resolved_schema = self._resolveSchemaReference(schema["$ref"])
            if resolved_schema:
                return self._generateComprehensiveExample(resolved_schema, depth + 1)
            else:
                return "unresolved_reference"
        
        if "type" not in schema:
            # Handle allOf, oneOf, anyOf with full property merging
            if "allOf" in schema:
                merged = {}
                for sub_schema in schema["allOf"]:
                    example = self._generateComprehensiveExample(sub_schema, depth + 1)
                    if isinstance(example, dict):
                        merged.update(example)
                return merged
            elif "oneOf" in schema and schema["oneOf"]:
                return self._generateComprehensiveExample(schema["oneOf"][0], depth + 1)
            elif "anyOf" in schema and schema["anyOf"]:
                return self._generateComprehensiveExample(schema["anyOf"][0], depth + 1)
            return {}
            
        schema_type = schema["type"]
        
        if schema_type == "object":
            obj = {}
            properties = schema.get("properties", {})
            required = schema.get("required", [])
            
            # Generate examples for ALL properties (not just required ones)
            # This matches Postman's comprehensive approach
            for prop_name, prop_schema in properties.items():
                try:
                    obj[prop_name] = self._generateComprehensiveExample(prop_schema, depth + 1)
                except Exception as e:
                    obj[prop_name] = "error_generating_" + prop_name
            
            return obj
            
        elif schema_type == "array":
            items = schema.get("items", {})
            min_items = schema.get("minItems", 1)
            max_items = min(schema.get("maxItems", 3), 3)  # Limit array size
            
            examples = []
            for i in range(max(min_items, 1)):
                if i < max_items:
                    examples.append(self._generateComprehensiveExample(items, depth + 1))
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
                elif format_type == "byte":
                    return "base64encodeddata"
            
            # Handle string constraints
            min_length = schema.get("minLength", 0)
            max_length = schema.get("maxLength", 50)
            
            # Generate more realistic examples based on field names
            field_name = schema.get("name", "example_string")
            if "name" in field_name.lower():
                base_value = "Service Name"
            elif "description" in field_name.lower():
                base_value = "Service description"
            elif "url" in field_name.lower():
                base_value = "https://api.example.com/endpoint"
            elif "code" in field_name.lower():
                base_value = "CODE123"
            elif "id" in field_name.lower():
                base_value = "12345"
            else:
                base_value = "string"
            
            # Apply length constraints
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
        
    def _sendRequest(self, event=None):
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
            
            # Build headers (ensure query string is included in the request line)
            parsed_url = urlparse(url)
            path_with_query = parsed_url.path + ("?" + parsed_url.query if parsed_url.query else "")
            headers = []
            headers.append(method + " " + path_with_query + " HTTP/1.1")
            headers.append("Host: " + parsed_url.netloc)
            
            # Check if this method actually has body parameters
            has_body_param = False
            if self.current_endpoint:
                details = self.current_endpoint["details"]
                parameters = details.get("parameters", [])
                for param in parameters:
                    if param.get("in") == "body":
                        has_body_param = True
                        break
            
            # Add content type (only for methods that support request bodies AND have body parameters)
            if method in ["POST", "PUT", "PATCH", "DELETE"] and has_body_param and content_type:
                headers.append("Content-Type: " + content_type)
                
            # Add headers from the request headers table (includes spec, auth, global, and manual headers)
            existing_accept = False
            for i in range(self._requestHeadersTableModel.getRowCount()):
                name = self._requestHeadersTableModel.getValueAt(i, 0)
                value = self._requestHeadersTableModel.getValueAt(i, 1)
                if name and value:  # Only add non-empty headers
                    headers.append(str(name) + ": " + str(value))
                    if str(name).strip().lower() == "accept":
                        existing_accept = True
                
            # Add default headers if enabled
            if self._includeDefaultHeadersCheck.isSelected():
                headers.append("User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36")
                
                # Check if Accept header already exists before adding default
                accept_exists = False
                for header in headers:
                    if header.lower().startswith("accept:"):
                        accept_exists = True
                        break
                
                if not accept_exists:
                    headers.append("Accept: */*")
                
            # Build full request (only add body for methods that support it AND have body parameters)
            if body and method in ["POST", "PUT", "PATCH", "DELETE"] and has_body_param:
                headers.append("Content-Length: " + str(len(body)))
                full_request = "\r\n".join(headers) + "\r\n\r\n" + body
                self._callbacks.printOutput("Adding body to " + method + " request (has body parameter)")
            else:
                # No body - either method doesn't support bodies or has no body parameter
                full_request = "\r\n".join(headers) + "\r\n\r\n"
                if not has_body_param:
                    self._callbacks.printOutput("No body added to " + method + " request (no body parameter defined)")
                else:
                    self._callbacks.printOutput("No body added to " + method + " request (method doesn't support bodies)")
                
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
    
    def _addAuthProfile(self, event):
        """Add a new authentication profile"""
        auth_type = str(self._authTypeCombo.getSelectedItem())
        profile_name = self._profileNameField.getText().strip()
        
        if not profile_name:
            JOptionPane.showMessageDialog(self._mainPanel, "Please enter a profile name", "Error", JOptionPane.ERROR_MESSAGE)
            return
        
        if auth_type == "None":
            JOptionPane.showMessageDialog(self._mainPanel, "Please select an authentication type", "Error", JOptionPane.ERROR_MESSAGE)
            return
        
        # Create auth profile
        auth_profile = {
            "name": profile_name,
            "type": auth_type,
            "key": self._authKeyField.getText().strip(),
            "value": self._authValueField.getText().strip()
        }
        
        # Initialize auth profiles if not exists
        if not hasattr(self, 'auth_profiles'):
            self.auth_profiles = []
        
        # Check if profile name already exists
        for profile in self.auth_profiles:
            if profile["name"] == profile_name:
                JOptionPane.showMessageDialog(self._mainPanel, "Profile name already exists", "Error", JOptionPane.ERROR_MESSAGE)
                return
        
        # Add profile
        self.auth_profiles.append(auth_profile)
        
        # Add to table
        self._addAuthProfileToTable(auth_profile)
        
        # Clear fields
        self._profileNameField.setText("")
        self._authKeyField.setText("")
        self._authValueField.setText("")
        
        JOptionPane.showMessageDialog(self._mainPanel, 
            "Authentication profile '" + profile_name + "' added successfully", 
            "Success", JOptionPane.INFORMATION_MESSAGE)
    
    def _addAuthProfileToTable(self, profile):
        """Add an authentication profile to the table"""
        # Create action buttons for the Actions column
        actions_panel = JPanel(FlowLayout(FlowLayout.CENTER, 2, 2))
        
        # Apply button
        apply_btn = JButton("Apply", actionPerformed=lambda e, p=profile: self._applyAuthProfile(p))
        apply_btn.setPreferredSize(Dimension(50, 20))
        apply_btn.setBackground(Color(60, 120, 60))
        apply_btn.setForeground(Color.WHITE)
        
        # Edit button
        edit_btn = JButton("Edit", actionPerformed=lambda e, p=profile: self._editAuthProfileFromTable(p))
        edit_btn.setPreferredSize(Dimension(50, 20))
        edit_btn.setBackground(Color(60, 60, 120))
        edit_btn.setForeground(Color.WHITE)
        
        actions_panel.add(apply_btn)
        actions_panel.add(edit_btn)
        
        # Add row to table
        self._authTableModel.addRow([
            profile["name"],
            profile["type"],
            profile["key"],
            profile["value"],
            actions_panel
        ])
    
    def _applyAuthProfile(self, profile):
        """Apply a specific authentication profile"""
        auth_type = profile["type"]
        self.auth_headers = {}
        
        if auth_type == "Bearer Token":
            token = profile["value"]
            if token:
                self.auth_headers["Authorization"] = "Bearer " + token
                
        elif auth_type == "API Key":
            header_name = profile["key"]
            api_key = profile["value"]
            if header_name and api_key:
                self.auth_headers[header_name] = api_key
                
        elif auth_type == "Basic Auth":
            username = profile["key"]
            password = profile["value"]
            if username and password:
                credentials = username + ":" + password
                encoded = base64.b64encode(credentials.encode('utf-8')).decode('utf-8')
                self.auth_headers["Authorization"] = "Basic " + encoded
                
        elif auth_type == "Custom Header":
            header_name = profile["key"]
            header_value = profile["value"]
            if header_name and header_value:
                self.auth_headers[header_name] = header_value
        
        # Refresh headers to show the updated authentication
        self._refreshHeadersFromSpec()
        
        JOptionPane.showMessageDialog(self._mainPanel,
            "Authentication profile '" + profile["name"] + "' applied successfully", 
            "Success", JOptionPane.INFORMATION_MESSAGE)
    
    def _editAuthProfileFromTable(self, profile):
        """Edit an authentication profile from the table"""
        # Populate fields with current values
        self._authTypeCombo.setSelectedItem(profile["type"])
        self._profileNameField.setText(profile["name"])
        self._authKeyField.setText(profile["key"])
        self._authValueField.setText(profile["value"])
        
        # Change button text
        if hasattr(self, '_addAuthButton'):
            self._addAuthButton.setText("Update Profile")
        
        # Store profile being edited
        self._editingProfile = profile
    
    def _editAuthProfile(self, event):
        """Edit selected authentication profile"""
        selected = self._authTable.getSelectedRow()
        if selected < 0:
            JOptionPane.showMessageDialog(self._mainPanel, "Please select a profile to edit", "Info", JOptionPane.INFORMATION_MESSAGE)
            return
        
        # Get profile from table
        profile_name = self._authTableModel.getValueAt(selected, 0)
        profile = None
        for p in self.auth_profiles:
            if p["name"] == profile_name:
                profile = p
                break
        
        if profile:
            self._editAuthProfileFromTable(profile)
        else:
            JOptionPane.showMessageDialog(self._mainPanel, "Profile not found", "Error", JOptionPane.ERROR_MESSAGE)
    
    def _deleteAuthProfile(self, event):
        """Delete selected authentication profile"""
        selected = self._authTable.getSelectedRow()
        if selected < 0:
            JOptionPane.showMessageDialog(self._mainPanel, "Please select a profile to delete", "Info", JOptionPane.INFORMATION_MESSAGE)
            return
        
        profile_name = self._authTableModel.getValueAt(selected, 0)
        
        # Confirm deletion
        result = JOptionPane.showConfirmDialog(self._mainPanel,
            "Are you sure you want to delete profile '" + profile_name + "'?",
            "Confirm Deletion", JOptionPane.YES_NO_OPTION)
        
        if result == JOptionPane.YES_OPTION:
            # Remove from profiles list
            self.auth_profiles = [p for p in self.auth_profiles if p["name"] != profile_name]
            
            # Remove from table
            self._authTableModel.removeRow(selected)
            
            JOptionPane.showMessageDialog(self._mainPanel,
                "Profile '" + profile_name + "' deleted successfully", 
                "Success", JOptionPane.INFORMATION_MESSAGE)
    
    def _applySelectedAuth(self, event):
        """Apply the selected authentication profile"""
        selected = self._authTable.getSelectedRow()
        if selected < 0:
            JOptionPane.showMessageDialog(self._mainPanel, "Please select a profile to apply", "Info", JOptionPane.INFORMATION_MESSAGE)
            return
        
        profile_name = self._authTableModel.getValueAt(selected, 0)
        profile = None
        for p in self.auth_profiles:
            if p["name"] == profile_name:
                profile = p
                break
        
        if profile:
            self._applyAuthProfile(profile)
        else:
            JOptionPane.showMessageDialog(self._mainPanel, "Profile not found", "Error", JOptionPane.ERROR_MESSAGE)
    
    def _clearAllAuth(self, event):
        """Clear all authentication profiles"""
        if not hasattr(self, 'auth_profiles') or not self.auth_profiles:
            JOptionPane.showMessageDialog(self._mainPanel, "No profiles to clear", "Info", JOptionPane.INFORMATION_MESSAGE)
            return
        
        result = JOptionPane.showConfirmDialog(self._mainPanel,
            "Are you sure you want to clear all authentication profiles?",
            "Confirm Clear All", JOptionPane.YES_NO_OPTION)
        
        if result == JOptionPane.YES_OPTION:
            self.auth_profiles = []
            self._authTableModel.setRowCount(0)
            self.auth_headers = {}
            self._refreshHeadersFromSpec()
            
            JOptionPane.showMessageDialog(self._mainPanel,
                "All authentication profiles cleared successfully", 
                "Success", JOptionPane.INFORMATION_MESSAGE)
    
    def _saveAuthProfiles(self, event):
        """Save authentication profiles to a file"""
        if not hasattr(self, 'auth_profiles') or not self.auth_profiles:
            JOptionPane.showMessageDialog(self._mainPanel, "No profiles to save", "Info", JOptionPane.INFORMATION_MESSAGE)
            return
        
        # Create file chooser
        file_chooser = JFileChooser()
        file_chooser.setDialogTitle("Save Authentication Profiles")
        file_chooser.setFileSelectionMode(JFileChooser.FILES_ONLY)
        file_chooser.setSelectedFile(JavaFile("auth_profiles.json"))
        
        result = file_chooser.showSaveDialog(self._mainPanel)
        if result == JFileChooser.APPROVE_OPTION:
            try:
                file_path = file_chooser.getSelectedFile().getAbsolutePath()
                
                # Save profiles to JSON file
                with open(file_path, 'w') as f:
                    json.dump(self.auth_profiles, f, indent=2)
                
                JOptionPane.showMessageDialog(self._mainPanel,
                    "Authentication profiles saved to:\n" + file_path, 
                    "Success", JOptionPane.INFORMATION_MESSAGE)
                    
            except Exception as e:
                JOptionPane.showMessageDialog(self._mainPanel,
                    "Error saving profiles: " + str(e), 
                    "Error", JOptionPane.ERROR_MESSAGE)
    
    def _loadAuthProfiles(self, event):
        """Load authentication profiles from a file"""
        # Create file chooser
        file_chooser = JFileChooser()
        file_chooser.setDialogTitle("Load Authentication Profiles")
        file_chooser.setFileSelectionMode(JFileChooser.FILES_ONLY)
        file_chooser.setFileFilter(javax.swing.filechooser.FileNameExtensionFilter("JSON files", "json"))
        
        result = file_chooser.showOpenDialog(self._mainPanel)
        if result == JFileChooser.APPROVE_OPTION:
            try:
                file_path = file_chooser.getSelectedFile().getAbsolutePath()
                
                # Load profiles from JSON file
                with open(file_path, 'r') as f:
                    loaded_profiles = json.load(f)
                
                # Validate profiles
                if not isinstance(loaded_profiles, list):
                    raise ValueError("Invalid file format: expected a list of profiles")
                
                # Clear existing profiles
                self.auth_profiles = []
                self._authTableModel.setRowCount(0)
                
                # Add loaded profiles
                for profile in loaded_profiles:
                    if isinstance(profile, dict) and 'name' in profile and 'type' in profile:
                        self.auth_profiles.append(profile)
                        self._addAuthProfileToTable(profile)
                
                JOptionPane.showMessageDialog(self._mainPanel,
                    "Loaded " + str(len(loaded_profiles)) + " authentication profiles from:\n" + file_path, 
                    "Success", JOptionPane.INFORMATION_MESSAGE)
                    
            except Exception as e:
                JOptionPane.showMessageDialog(self._mainPanel,
                    "Error loading profiles: " + str(e), 
                    "Error", JOptionPane.ERROR_MESSAGE)
    
    def _createHeadersTableMouseListener(self):
        """Create mouse listener for headers table to handle enabled column clicks"""
        class HeadersTableMouseListener(MouseAdapter):
            def __init__(self, extender):
                self.extender = extender
            
            def mouseClicked(self, event):
                # Check if click is on the Enabled column (column 3)
                column = self.extender._headersTable.columnAtPoint(event.getPoint())
                if column == 3:  # Enabled column
                    row = self.extender._headersTable.rowAtPoint(event.getPoint())
                    if row >= 0:
                        # Toggle enabled status
                        current_status = self.extender._headersTableModel.getValueAt(row, 3)
                        new_status = "✗" if current_status == "✓" else "✓"
                        
                        # Update table
                        self.extender._headersTableModel.setValueAt(new_status, row, 3)
                        
                        # Update stored header data
                        header_name = self.extender._headersTableModel.getValueAt(row, 0)
                        if hasattr(self.extender, 'custom_headers'):
                            for header in self.extender.custom_headers:
                                if header["name"] == header_name:
                                    header["enabled"] = (new_status == "✓")
                                    break
                        
                        # Refresh headers in API Tester tab
                        self.extender._refreshHeadersFromSpec()
                        
                        # Show feedback
                        status_text = "enabled" if new_status == "✓" else "disabled"
                        self.extender._callbacks.printOutput("Header '" + header_name + "' " + status_text)
        
        return HeadersTableMouseListener(self)
    
    def _createRequestShortcutListener(self):
        """Create keyboard shortcut listener for sending requests and endpoint management"""
        class RequestShortcutListener(KeyAdapter):
            def __init__(self, extender):
                self.extender = extender
            
            def keyPressed(self, event):
                # Check for Control+Space (Send Request)
                if event.getKeyCode() == KeyEvent.VK_SPACE and event.isControlDown():
                    # Only send if an endpoint is selected
                    if self.extender.current_endpoint:
                        # Consume the event to prevent default behavior
                        event.consume()
                        # Send the request in a separate thread to avoid UI blocking
                        from threading import Thread
                        Thread(target=self.extender._sendRequest).start()
                    else:
                        JOptionPane.showMessageDialog(self.extender._mainPanel,
                            "Please select an endpoint first", 
                            "No Endpoint Selected", JOptionPane.INFORMATION_MESSAGE)
                
                # Check for Delete key (Remove selected endpoint)
                elif event.getKeyCode() == KeyEvent.VK_DELETE:
                    if self.extender._endpointList.getSelectedIndices():
                        event.consume()
                        self.extender._removeSelectedEndpoint(None)
                    else:
                        JOptionPane.showMessageDialog(self.extender._mainPanel,
                            "Please select an endpoint to remove", 
                            "No Endpoint Selected", JOptionPane.INFORMATION_MESSAGE)
                
                # Check for Control+Delete (Clear all endpoints)
                elif event.getKeyCode() == KeyEvent.VK_DELETE and event.isControlDown():
                    event.consume()
                    self.extender._clearAllEndpoints(None)
            
            def keyTyped(self, event):
                # Check for Control+Space (Send Request)
                if event.getKeyChar() == ' ' and event.isControlDown():
                    if self.extender.current_endpoint:
                        event.consume()
                        from threading import Thread
                        Thread(target=self.extender._sendRequest).start()
                    else:
                        JOptionPane.showMessageDialog(self.extender._mainPanel,
                            "Please select an endpoint first", 
                            "No Endpoint Selected", JOptionPane.INFORMATION_MESSAGE)
                
                # Check for Control+R (Send to Repeater)
                elif event.getKeyChar() == 'r' and event.isControlDown():
                    if self.extender.current_endpoint:
                        event.consume()
                        from threading import Thread
                        Thread(target=self.extender._sendToRepeater).start()
                    else:
                        JOptionPane.showMessageDialog(self.extender._mainPanel,
                            "Please select an endpoint first", 
                            "No Endpoint Selected", JOptionPane.INFORMATION_MESSAGE)
                
                # Check for Control+I (Send to Intruder)
                elif event.getKeyChar() == 'i' and event.isControlDown():
                    if self.extender.current_endpoint:
                        event.consume()
                        from threading import Thread
                        Thread(target=self.extender._sendToIntruder).start()
                    else:
                        JOptionPane.showMessageDialog(self.extender._mainPanel,
                            "Please select an endpoint first", 
                            "No Endpoint Selected", JOptionPane.INFORMATION_MESSAGE)
                
                # Check for Control+O (Send to Scanner)
                elif event.getKeyChar() == 'o' and event.isControlDown():
                    if self.extender.current_endpoint:
                        event.consume()
                        from threading import Thread
                        Thread(target=self.extender._sendToScanner).start()
                    else:
                        JOptionPane.showMessageDialog(self.extender._mainPanel,
                            "Please select an endpoint first", 
                            "No Endpoint Selected", JOptionPane.INFORMATION_MESSAGE)
        
        return RequestShortcutListener(self)
    
    def _addSwingKeyBindings(self):
        """Add Swing key bindings for keyboard shortcuts (more reliable than KeyListener)"""
        try:
            from javax.swing import AbstractAction, KeyStroke
            from java.awt.event import InputEvent
            
            # Create actions for different shortcuts
            class SendRequestAction(AbstractAction):
                def __init__(self, extender):
                    self.extender = extender
                    super(SendRequestAction, self).__init__("sendRequest")
                
                def actionPerformed(self, event):
                    if self.extender.current_endpoint:
                        from threading import Thread
                        Thread(target=self.extender._sendRequest).start()
                    else:
                        JOptionPane.showMessageDialog(self.extender._mainPanel,
                            "Please select an endpoint first", 
                            "No Endpoint Selected", JOptionPane.INFORMATION_MESSAGE)
            
            class SendToRepeaterAction(AbstractAction):
                def __init__(self, extender):
                    self.extender = extender
                    super(SendToRepeaterAction, self).__init__("sendToRepeater")
                
                def actionPerformed(self, event):
                    if self.extender.current_endpoint:
                        from threading import Thread
                        Thread(target=self.extender._sendToRepeater).start()
                    else:
                        JOptionPane.showMessageDialog(self.extender._mainPanel,
                            "Please select an endpoint first", 
                            "No Endpoint Selected", JOptionPane.INFORMATION_MESSAGE)
            
            class SendToIntruderAction(AbstractAction):
                def __init__(self, extender):
                    self.extender = extender
                    super(SendToIntruderAction, self).__init__("sendToIntruder")
                
                def actionPerformed(self, event):
                    if self.extender.current_endpoint:
                        from threading import Thread
                        Thread(target=self.extender._sendToIntruder).start()
                    else:
                        JOptionPane.showMessageDialog(self.extender._mainPanel,
                            "Please select an endpoint first", 
                            "No Endpoint Selected", JOptionPane.INFORMATION_MESSAGE)
            
            class SendToScannerAction(AbstractAction):
                def __init__(self, extender):
                    self.extender = extender
                    super(SendToScannerAction, self).__init__("sendToScanner")
                
                def actionPerformed(self, event):
                    if self.extender.current_endpoint:
                        from threading import Thread
                        Thread(target=self.extender._sendToScanner).start()
                    else:
                        JOptionPane.showMessageDialog(self.extender._mainPanel,
                            "Please select an endpoint first", 
                            "No Endpoint Selected", JOptionPane.INFORMATION_MESSAGE)
            
            # Create action instances
            sendRequestAction = SendRequestAction(self)
            sendToRepeaterAction = SendToRepeaterAction(self)
            sendToIntruderAction = SendToIntruderAction(self)
            sendToScannerAction = SendToScannerAction(self)
            
            # Create key strokes for all shortcuts
            ctrl_space = KeyStroke.getKeyStroke(KeyEvent.VK_SPACE, InputEvent.CTRL_DOWN_MASK)
            ctrl_r = KeyStroke.getKeyStroke(KeyEvent.VK_R, InputEvent.CTRL_DOWN_MASK)
            ctrl_i = KeyStroke.getKeyStroke(KeyEvent.VK_I, InputEvent.CTRL_DOWN_MASK)
            ctrl_o = KeyStroke.getKeyStroke(KeyEvent.VK_O, InputEvent.CTRL_DOWN_MASK)
            
            # Apply to all relevant components
            components = [self._endpointList, self._requestEditor, self._requestUrlField]
            
            for component in components:
                if hasattr(component, 'getInputMap') and hasattr(component, 'getActionMap'):
                    input_map = component.getInputMap()
                    action_map = component.getActionMap()
                    
                    # Add all key combinations
                    input_map.put(ctrl_space, "sendRequest")
                    input_map.put(ctrl_r, "sendToRepeater")
                    input_map.put(ctrl_i, "sendToIntruder")
                    input_map.put(ctrl_o, "sendToScanner")
                    
                    action_map.put("sendRequest", sendRequestAction)
                    action_map.put("sendToRepeater", sendToRepeaterAction)
                    action_map.put("sendToIntruder", sendToIntruderAction)
                    action_map.put("sendToScanner", sendToScannerAction)
            
            self._callbacks.printOutput("Keyboard shortcuts configured successfully")
            
        except Exception as e:
            self._callbacks.printError("Error adding Swing key bindings: " + str(e))
            
    # Header override management
    def _addHeaderOverride(self, event):
        name = JOptionPane.showInputDialog(self._mainPanel, "Header Name to Override (case-insensitive):")
        if not name:
            return
        value = JOptionPane.showInputDialog(self._mainPanel, "New Value for '" + str(name) + "':")
        if value is None:
            return
        enable_now = JOptionPane.showConfirmDialog(self._mainPanel,
            "Enable this override now?", "Enable Override",
            JOptionPane.YES_NO_OPTION)
        enabled = (enable_now == JOptionPane.YES_OPTION)
        
        if not hasattr(self, 'header_overrides'):
            self.header_overrides = []
        self.header_overrides.append({ 'name': str(name), 'value': str(value), 'enabled': enabled })
        self._headerOverridesTableModel.addRow([str(name), str(value), "✓" if enabled else "✗"])
        self._refreshHeadersFromSpec()

    def _editHeaderOverride(self, event):
        row = self._headerOverridesTable.getSelectedRow()
        if row < 0:
            JOptionPane.showMessageDialog(self._mainPanel, "Select an override to edit", "Info", JOptionPane.INFORMATION_MESSAGE)
            return
        current_name = self._headerOverridesTableModel.getValueAt(row, 0)
        current_value = self._headerOverridesTableModel.getValueAt(row, 1)
        current_enabled = self._headerOverridesTableModel.getValueAt(row, 2) == "✓"
        
        name = JOptionPane.showInputDialog(self._mainPanel, "Header Name:", current_name)
        if not name:
            return
        value = JOptionPane.showInputDialog(self._mainPanel, "New Value:", current_value)
        if value is None:
            return
        enable_now = JOptionPane.showConfirmDialog(self._mainPanel,
            "Enable this override?", "Enable Override",
            JOptionPane.YES_NO_OPTION)
        enabled = (enable_now == JOptionPane.YES_OPTION)
        
        self._headerOverridesTableModel.setValueAt(name, row, 0)
        self._headerOverridesTableModel.setValueAt(value, row, 1)
        self._headerOverridesTableModel.setValueAt("✓" if enabled else "✗", row, 2)
        
        updated = False
        for o in getattr(self, 'header_overrides', []):
            if o.get('name', '').lower() == str(current_name).lower():
                o['name'] = str(name)
                o['value'] = str(value)
                o['enabled'] = enabled
                updated = True
                break
        if not updated:
            self.header_overrides.append({ 'name': str(name), 'value': str(value), 'enabled': enabled })
        self._refreshHeadersFromSpec()

    def _removeHeaderOverride(self, event):
        row = self._headerOverridesTable.getSelectedRow()
        if row < 0:
            JOptionPane.showMessageDialog(self._mainPanel, "Select an override to remove", "Info", JOptionPane.INFORMATION_MESSAGE)
            return
        name = self._headerOverridesTableModel.getValueAt(row, 0)
        self._headerOverridesTableModel.removeRow(row)
        if hasattr(self, 'header_overrides'):
            self.header_overrides = [o for o in self.header_overrides if o.get('name', '').lower() != str(name).lower()]
        self._refreshHeadersFromSpec()

    def _applyHeaderOverrides(self, event=None):
        self._refreshHeadersFromSpec()

    def _testKeyboardShortcut(self, event):
        """Test keyboard shortcut system"""
        try:
            self._callbacks.printOutput("=== KEYBOARD SHORTCUT TEST ===")
            self._callbacks.printOutput("Current endpoint: " + str(self.current_endpoint))
            self._callbacks.printOutput("Endpoint list focus: " + str(self._endpointList.hasFocus()))
            self._callbacks.printOutput("Request editor focus: " + str(self._requestEditor.hasFocus()))
            self._callbacks.printOutput("Request URL focus: " + str(self._requestUrlField.hasFocus()))
            
            # Test if components have key listeners
            endpoint_listeners = self._endpointList.getKeyListeners()
            editor_listeners = self._requestEditor.getKeyListeners()
            url_listeners = self._requestUrlField.getKeyListeners()
            
            self._callbacks.printOutput("Endpoint list key listeners: " + str(len(endpoint_listeners)))
            self._callbacks.printOutput("Request editor key listeners: " + str(len(editor_listeners)))
            self._callbacks.printOutput("Request URL key listeners: " + str(len(url_listeners)))
            
            # Show dialog with info
            info = "Keyboard Shortcut Test Results:\n\n"
            info += "Current endpoint: " + ("Selected" if self.current_endpoint else "None") + "\n"
            info += "Key listeners attached: " + str(len(endpoint_listeners) + len(editor_listeners) + len(url_listeners)) + "\n\n"
            info += "To test shortcut:\n"
            info += "1. Focus on endpoint list, URL field, or request editor\n"
            info += "2. Press Control+Space\n"
            info += "3. Check console output for debug messages"
            
            JOptionPane.showMessageDialog(self._mainPanel, info, "Keyboard Shortcut Test", JOptionPane.INFORMATION_MESSAGE)
            
        except Exception as e:
            self._callbacks.printError("Error in keyboard shortcut test: " + str(e))

    def _addHeader(self, event):
        """Add custom header with enhanced dialog"""
        # Create custom dialog for header input
        headerDialog = JPanel()
        headerDialog.setLayout(GroupLayout(headerDialog))
        headerLayout = GroupLayout(headerDialog)
        headerDialog.setLayout(headerLayout)
        headerLayout.setAutoCreateGaps(True)
        headerLayout.setAutoCreateContainerGaps(True)
        
        # Header name field
        nameLabel = JLabel("Header Name:")
        nameField = JTextField(20)
        nameField.setText("X-Custom-Header")
        
        # Header value field
        valueLabel = JLabel("Header Value:")
        valueField = JTextField(30)
        valueField.setText("custom-value")
        
        # Description field
        descLabel = JLabel("Description:")
        descField = JTextField(25)
        descField.setText("Custom header for all requests")
        
        # Enabled checkbox
        enabledCheck = JCheckBox("Enabled", True)
        
        # Layout the dialog
        headerLayout.setHorizontalGroup(
            headerLayout.createParallelGroup()
                .addGroup(headerLayout.createSequentialGroup()
                    .addComponent(nameLabel)
                    .addComponent(nameField))
                .addGroup(headerLayout.createSequentialGroup()
                    .addComponent(valueLabel)
                    .addComponent(valueField))
                .addGroup(headerLayout.createSequentialGroup()
                    .addComponent(descLabel)
                    .addComponent(descField))
                .addComponent(enabledCheck)
        )
        
        headerLayout.setVerticalGroup(
            headerLayout.createSequentialGroup()
                .addGroup(headerLayout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(nameLabel)
                    .addComponent(nameField))
                .addGroup(headerLayout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(valueLabel)
                    .addComponent(valueField))
                .addGroup(headerLayout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(descLabel)
                    .addComponent(descField))
                .addComponent(enabledCheck)
        )
        
        # Show dialog
        result = JOptionPane.showConfirmDialog(self._mainPanel, headerDialog, 
            "Add Custom Header", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE)
        
        if result == JOptionPane.OK_OPTION:
            name = nameField.getText().strip()
            value = valueField.getText().strip()
            description = descField.getText().strip()
            enabled = enabledCheck.isSelected()
            
            if name and value:
                # Add to table
                self._headersTableModel.addRow([name, value, description, "✓" if enabled else "✗"])
                
                # Store header data for later use
                if not hasattr(self, 'custom_headers'):
                    self.custom_headers = []
                
                header_data = {
                    "name": name,
                    "value": value,
                    "description": description,
                    "enabled": enabled
                }
                self.custom_headers.append(header_data)
                
                # Refresh headers in API Tester tab
                self._refreshHeadersFromSpec()
                
                JOptionPane.showMessageDialog(self._mainPanel,
                    "Custom header '" + name + "' added successfully", 
                    "Success", JOptionPane.INFORMATION_MESSAGE)
            else:
                JOptionPane.showMessageDialog(self._mainPanel,
                    "Header name and value are required", 
                    "Error", JOptionPane.ERROR_MESSAGE)
    
    def _editHeader(self, event):
        """Edit selected custom header"""
        selected = self._headersTable.getSelectedRow()
        if selected < 0:
            JOptionPane.showMessageDialog(self._mainPanel, "Please select a header to edit", "Info", JOptionPane.INFORMATION_MESSAGE)
            return
        
        # Get current values
        name = self._headersTableModel.getValueAt(selected, 0)
        value = self._headersTableModel.getValueAt(selected, 1)
        description = self._headersTableModel.getValueAt(selected, 2)
        enabled = self._headersTableModel.getValueAt(selected, 3) == "✓"
        
        # Create edit dialog
        headerDialog = JPanel()
        headerDialog.setLayout(GroupLayout(headerDialog))
        headerLayout = GroupLayout(headerDialog)
        headerDialog.setLayout(headerLayout)
        headerLayout.setAutoCreateGaps(True)
        headerLayout.setAutoCreateContainerGaps(True)
        
        # Header name field
        nameLabel = JLabel("Header Name:")
        nameField = JTextField(20)
        nameField.setText(name)
        
        # Header value field
        valueLabel = JLabel("Header Value:")
        valueField = JTextField(30)
        valueField.setText(value)
        
        # Description field
        descLabel = JLabel("Description:")
        descField = JTextField(25)
        descField.setText(description)
        
        # Enabled checkbox
        enabledCheck = JCheckBox("Enabled", enabled)
        
        # Layout the dialog
        headerLayout.setHorizontalGroup(
            headerLayout.createParallelGroup()
                .addGroup(headerLayout.createSequentialGroup()
                    .addComponent(nameLabel)
                    .addComponent(nameField))
                .addGroup(headerLayout.createSequentialGroup()
                    .addComponent(valueLabel)
                    .addComponent(valueField))
                .addGroup(headerLayout.createSequentialGroup()
                    .addComponent(descLabel)
                    .addComponent(descField))
                .addComponent(enabledCheck)
        )
        
        headerLayout.setVerticalGroup(
            headerLayout.createSequentialGroup()
                .addGroup(headerLayout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(nameLabel)
                    .addComponent(nameField))
                .addGroup(headerLayout.createSequentialGroup()
                    .addComponent(valueLabel)
                    .addComponent(valueField))
                .addGroup(headerLayout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(descLabel)
                    .addComponent(descField))
                .addComponent(enabledCheck)
        )
        
        # Show dialog
        result = JOptionPane.showConfirmDialog(self._mainPanel, headerDialog, 
            "Edit Custom Header", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE)
        
        if result == JOptionPane.OK_OPTION:
            new_name = nameField.getText().strip()
            new_value = valueField.getText().strip()
            new_description = descField.getText().strip()
            new_enabled = enabledCheck.isSelected()
            
            if new_name and new_value:
                # Update table
                self._headersTableModel.setValueAt(new_name, selected, 0)
                self._headersTableModel.setValueAt(new_value, selected, 1)
                self._headersTableModel.setValueAt(new_description, selected, 2)
                self._headersTableModel.setValueAt("✓" if new_enabled else "✗", selected, 3)
                
                # Update stored header data
                if hasattr(self, 'custom_headers'):
                    for header in self.custom_headers:
                        if header["name"] == name:  # Find by old name
                            header["name"] = new_name
                            header["value"] = new_value
                            header["description"] = new_description
                            header["enabled"] = new_enabled
                            break
                
                # Refresh headers in API Tester tab
                self._refreshHeadersFromSpec()
                
                JOptionPane.showMessageDialog(self._mainPanel,
                    "Custom header updated successfully", 
                    "Success", JOptionPane.INFORMATION_MESSAGE)
            else:
                JOptionPane.showMessageDialog(self._mainPanel,
                    "Header name and value are required", 
                    "Error", JOptionPane.ERROR_MESSAGE)
                
    def _removeHeader(self, event):
        """Remove selected custom header"""
        selected = self._headersTable.getSelectedRow()
        if selected < 0:
            JOptionPane.showMessageDialog(self._mainPanel, "Please select a header to remove", "Info", JOptionPane.INFORMATION_MESSAGE)
            return
        
        header_name = self._headersTableModel.getValueAt(selected, 0)
        
        # Confirm deletion
        result = JOptionPane.showConfirmDialog(self._mainPanel,
            "Are you sure you want to remove header '" + header_name + "'?",
            "Confirm Removal", JOptionPane.YES_NO_OPTION)
        
        if result == JOptionPane.YES_OPTION:
            # Remove from table
            self._headersTableModel.removeRow(selected)
            
            # Remove from stored headers
            if hasattr(self, 'custom_headers'):
                self.custom_headers = [h for h in self.custom_headers if h["name"] != header_name]
            
            # Refresh headers in API Tester tab
            self._refreshHeadersFromSpec()
            
            JOptionPane.showMessageDialog(self._mainPanel,
                "Header '" + header_name + "' removed successfully", 
                "Success", JOptionPane.INFORMATION_MESSAGE)
    
    def _clearAllHeaders(self, event):
        """Clear all custom headers"""
        if not hasattr(self, 'custom_headers') or not self.custom_headers:
            JOptionPane.showMessageDialog(self._mainPanel, "No headers to clear", "Info", JOptionPane.INFORMATION_MESSAGE)
            return
        
        result = JOptionPane.showConfirmDialog(self._mainPanel,
            "Are you sure you want to clear all custom headers?",
            "Confirm Clear All", JOptionPane.YES_NO_OPTION)
        
        if result == JOptionPane.YES_OPTION:
            self.custom_headers = []
            self._headersTableModel.setRowCount(0)
            
            # Refresh headers in API Tester tab
            self._refreshHeadersFromSpec()
            
            JOptionPane.showMessageDialog(self._mainPanel,
                "All custom headers cleared successfully", 
                "Success", JOptionPane.INFORMATION_MESSAGE)
    
    def _saveHeaders(self, event):
        """Save custom headers to a file"""
        if not hasattr(self, 'custom_headers') or not self.custom_headers:
            JOptionPane.showMessageDialog(self._mainPanel, "No headers to save", "Info", JOptionPane.INFORMATION_MESSAGE)
            return
        
        # Create file chooser
        file_chooser = JFileChooser()
        file_chooser.setDialogTitle("Save Custom Headers")
        file_chooser.setFileSelectionMode(JFileChooser.FILES_ONLY)
        file_chooser.setSelectedFile(JavaFile("custom_headers.json"))
        
        result = file_chooser.showSaveDialog(self._mainPanel)
        if result == JFileChooser.APPROVE_OPTION:
            try:
                file_path = file_chooser.getSelectedFile().getAbsolutePath()
                
                # Save headers to JSON file
                with open(file_path, 'w') as f:
                    json.dump(self.custom_headers, f, indent=2)
                
                JOptionPane.showMessageDialog(self._mainPanel,
                    "Custom headers saved to:\n" + file_path, 
                    "Success", JOptionPane.INFORMATION_MESSAGE)
                    
            except Exception as e:
                JOptionPane.showMessageDialog(self._mainPanel,
                    "Error saving headers: " + str(e), 
                    "Error", JOptionPane.ERROR_MESSAGE)
    
    def _loadHeaders(self, event):
        """Load custom headers from a file"""
        # Create file chooser
        file_chooser = JFileChooser()
        file_chooser.setDialogTitle("Load Custom Headers")
        file_chooser.setFileSelectionMode(JFileChooser.FILES_ONLY)
        file_chooser.setFileFilter(javax.swing.filechooser.FileNameExtensionFilter("JSON files", "json"))
        
        result = file_chooser.showOpenDialog(self._mainPanel)
        if result == JFileChooser.APPROVE_OPTION:
            try:
                file_path = file_chooser.getSelectedFile().getAbsolutePath()
                
                # Load headers from JSON file
                with open(file_path, 'r') as f:
                    loaded_headers = json.load(f)
                
                # Validate headers
                if not isinstance(loaded_headers, list):
                    raise ValueError("Invalid file format: expected a list of headers")
                
                # Clear existing headers
                self.custom_headers = []
                self._headersTableModel.setRowCount(0)
                
                # Add loaded headers
                for header in loaded_headers:
                    if isinstance(header, dict) and 'name' in header and 'value' in header:
                        self.custom_headers.append(header)
                        enabled_symbol = "✓" if header.get("enabled", True) else "✗"
                        description = header.get("description", "")
                        self._headersTableModel.addRow([
                            header["name"], 
                            header["value"], 
                            description, 
                            enabled_symbol
                        ])
                
                # Refresh headers in API Tester tab
                self._refreshHeadersFromSpec()
                
                JOptionPane.showMessageDialog(self._mainPanel,
                    "Loaded " + str(len(loaded_headers)) + " custom headers from:\n" + file_path, 
                    "Success", JOptionPane.INFORMATION_MESSAGE)
                    
            except Exception as e:
                JOptionPane.showMessageDialog(self._mainPanel,
                    "Error loading headers: " + str(e), 
                    "Error", JOptionPane.ERROR_MESSAGE)
            

        

        

    
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
                
                if name:
                    # Provide sensible defaults for common headers if value missing
                    if (value is None) or (str(value).strip() == ""):
                        lname = str(name).strip().lower()
                        if lname == "accept":
                            # Infer Accept from spec (operation/global produces or response content)
                            try:
                                value = self._inferAcceptHeader()
                            except:
                                value = "application/json"
                        elif lname == "accept-language":
                            value = "en-US"
                        elif lname == "content-type":
                            try:
                                value = str(self._contentTypeCombo.getSelectedItem())
                            except:
                                value = "application/json"
                        else:
                            value = ""
                    
                    # Always add spec headers so the user can edit missing values
                    self._requestHeadersTableModel.addRow([name, value, "Spec"])
        
        # Add global authentication headers (always, regardless of endpoint selection)
        for header, value in self.auth_headers.items():
            if header and value:
                self._requestHeadersTableModel.addRow([header, value, "Auth"])
        
        # Add global custom headers (always, regardless of endpoint selection)
        if hasattr(self, 'custom_headers'):
            for header in self.custom_headers:
                if header.get("enabled", True) and header.get("name") and header.get("value"):
                    self._requestHeadersTableModel.addRow([header["name"], header["value"], "Global"])

        # Apply header overrides (update existing rows by header name) and ensure presence
        try:
            overrides = getattr(self, 'header_overrides', [])
            if overrides and self._requestHeadersTableModel.getRowCount() > 0:
                for override in overrides:
                    if not override:
                        continue
                    name = str(override.get('name', '')).strip()
                    new_value = override.get('value', '')
                    enabled = override.get('enabled', True)
                    if not enabled or not name:
                        continue
                    # Scan rows and update matching header names
                    for i in range(self._requestHeadersTableModel.getRowCount()):
                        row_name = str(self._requestHeadersTableModel.getValueAt(i, 0)).strip()
                        if row_name.lower() == name.lower():
                            self._requestHeadersTableModel.setValueAt(new_value, i, 1)
                            break
                    else:
                        # If not present at all, add it as an Override source to take precedence
                        self._requestHeadersTableModel.addRow([name, new_value, "Override"])                    
        except Exception as e:
            self._callbacks.printError("Error applying header overrides: " + str(e))

    def _inferAcceptHeader(self):
        """Infer the best Accept header based on the spec and selected operation"""
        # Priority:
        # 1) Operation-level produces (Swagger 2.0)
        # 2) Global produces (Swagger 2.0)
        # 3) Operation success response content types (OpenAPI 3.0)
        # 4) Current content-type selection
        # 5) Fallback to application/json
        try:
            # Operation-level (Swagger 2.0)
            if self.current_endpoint:
                details = self.current_endpoint.get('details', {})
                if isinstance(details, dict) and 'produces' in details and details['produces']:
                    return details['produces'][0]
                
                # OpenAPI 3.0: infer from 2xx responses content
                if 'responses' in details:
                    for code, resp in details['responses'].items():
                        if str(code).startswith('2') and isinstance(resp, dict):
                            content = resp.get('content')
                            if isinstance(content, dict) and content:
                                return list(content.keys())[0]
            
            # Global level (Swagger 2.0)
            if self.swagger_spec and 'produces' in self.swagger_spec and self.swagger_spec['produces']:
                return self.swagger_spec['produces'][0]
            
            # Current selection
            if hasattr(self, '_contentTypeCombo'):
                ct = str(self._contentTypeCombo.getSelectedItem())
                if ct and ct.strip():
                    return ct
        except:
            pass
        return 'application/json'
    
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
                self._updateEndpointCountLabel()
                
                self._callbacks.printOutput("All endpoint URLs updated for new base URL: " + self.base_url)
        except Exception as e:
            self._callbacks.printError("Error updating endpoint URLs: " + str(e))
    
    def _createEndpointListMouseListener(self):
        """Create mouse listener for endpoint list context menu"""
        class EndpointListMouseListener(MouseAdapter):
            def __init__(self, parent):
                self.parent = parent
                self._endpointListPopup = None
            
            def mousePressed(self, event):
                if event.isPopupTrigger():
                    self._showContextMenu(event)
            
            def mouseReleased(self, event):
                if event.isPopupTrigger():
                    self._showContextMenu(event)
            
            def _showContextMenu(self, event):
                # Get the clicked location
                clicked_index = self.parent._endpointList.locationToIndex(event.getPoint())
                
                # Check if we clicked on an item
                if clicked_index >= 0:
                    # Select the clicked item if it's not already selected
                    if not self.parent._endpointList.isSelectedIndex(clicked_index):
                        self.parent._endpointList.setSelectedIndex(clicked_index)
                    
                    # Create and show context menu
                    self._createContextMenu(event, clicked_index)
                else:
                    # Clicked on empty space - show general context menu
                    self._createContextMenu(event, -1)
            
            def _createContextMenu(self, event, clicked_index):
                self._endpointListPopup = JPopupMenu()
                
                # Get selected indices
                selected_indices = self.parent._endpointList.getSelectedIndices()
                
                if clicked_index >= 0 and len(selected_indices) > 0:
                    # Item-specific actions
                    if len(selected_indices) == 1:
                        # Single item selected
                        endpoint_text = self.parent._endpointListModel.getElementAt(clicked_index)
                        
                        # Remove this endpoint
                        removeItem = JMenuItem("Remove Endpoint", actionPerformed=lambda e: self.parent._removeSelectedEndpoint(None))
                        removeItem.setToolTipText("Remove this endpoint from the list")
                        self._endpointListPopup.add(removeItem)
                        
                        # Copy endpoint info
                        copyItem = JMenuItem("Copy Endpoint Info", actionPerformed=lambda e: self._copyEndpointInfo(endpoint_text))
                        copyItem.setToolTipText("Copy endpoint method and path to clipboard")
                        self._endpointListPopup.add(copyItem)
                        
                    else:
                        # Multiple items selected
                        removeMultipleItem = JMenuItem("Remove Selected ({})".format(len(selected_indices)), 
                                                     actionPerformed=lambda e: self.parent._removeMultipleEndpoints(None))
                        removeMultipleItem.setToolTipText("Remove all selected endpoints")
                        self._endpointListPopup.add(removeMultipleItem)
                        
                        # Copy all selected endpoints
                        copyAllItem = JMenuItem("Copy All Selected", 
                                              actionPerformed=lambda e: self._copyAllSelectedEndpoints(selected_indices))
                        copyAllItem.setToolTipText("Copy all selected endpoint info to clipboard")
                        self._endpointListPopup.add(copyAllItem)
                    
                    self._endpointListPopup.addSeparator()
                
                # General actions
                if self.parent._endpointListModel.getSize() > 0:
                    clearAllItem = JMenuItem("Clear All Endpoints", actionPerformed=lambda e: self.parent._clearAllEndpoints(None))
                    clearAllItem.setToolTipText("Remove all endpoints from the list")
                    self._endpointListPopup.add(clearAllItem)
                
                # Show the popup menu
                if self._endpointListPopup.getComponentCount() > 0:
                    self._endpointListPopup.show(self.parent._endpointList, event.getX(), event.getY())
            
            def _copyEndpointInfo(self, endpoint_text):
                """Copy endpoint info to clipboard"""
                try:
                    from java.awt import Toolkit
                    from java.awt.datatransfer import StringSelection, Clipboard
                    
                    toolkit = Toolkit.getDefaultToolkit()
                    clipboard = toolkit.getSystemClipboard()
                    selection = StringSelection(endpoint_text)
                    clipboard.setContents(selection, selection)
                    
                    self.parent._callbacks.printOutput("Copied endpoint info: " + endpoint_text)
                except Exception as e:
                    self.parent._callbacks.printError("Error copying to clipboard: " + str(e))
            
            def _copyAllSelectedEndpoints(self, selected_indices):
                """Copy all selected endpoint info to clipboard"""
                try:
                    from java.awt import Toolkit
                    from java.awt.datatransfer import StringSelection, Clipboard
                    
                    endpoint_texts = []
                    for index in selected_indices:
                        if index < self.parent._endpointListModel.getSize():
                            endpoint_text = self.parent._endpointListModel.getElementAt(index)
                            endpoint_texts.append(endpoint_text)
                    
                    if endpoint_texts:
                        clipboard_text = "\n".join(endpoint_texts)
                        from java.awt import Toolkit
                        from java.awt.datatransfer import StringSelection, Clipboard
                        
                        toolkit = Toolkit.getDefaultToolkit()
                        clipboard = toolkit.getSystemClipboard()
                        selection = StringSelection(clipboard_text)
                        clipboard.setContents(selection, selection)
                        
                        self.parent._callbacks.printOutput("Copied {} endpoints to clipboard".format(len(endpoint_texts)))
                except Exception as e:
                    self.parent._callbacks.printError("Error copying to clipboard: " + str(e))
        
        return EndpointListMouseListener(self)
    
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
        
        # Add separator and additional useful options
        self._requestPopup.addSeparator()
        
        # Copy URL
        copyUrl = JMenuItem("Copy URL", actionPerformed=lambda e: self._copyUrl())
        self._requestPopup.add(copyUrl)
        
        # Copy method
        copyMethod = JMenuItem("Copy HTTP Method", actionPerformed=lambda e: self._copyMethod())
        self._requestPopup.add(copyMethod)
    
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
            self._responseEditor.setText("")
            return
            
        # If it's already a full HTTP response, highlight it
        if text.startswith("HTTP/"):
            try:
                self.syntax_highlighter.highlight_http_response(self._responseEditor, text)
            except Exception as e:
                self._callbacks.printError("Response highlighting error: " + str(e))
                self._responseEditor.setText(text)
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
                self.syntax_highlighter.highlight_http_response(self._responseEditor, full_response)
            except Exception as e:
                self._callbacks.printError("Response highlighting error: " + str(e))
                self._responseEditor.setText(text)
    
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
                
                # Check if Accept header already exists before adding default
                accept_exists = False
                for header in headers:
                    if header.lower().startswith("accept:"):
                        accept_exists = True
                        break
                
                if not accept_exists:
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
        try:
            # Check if we have at least a URL and method
            url = self._requestUrlField.getText().strip()
            method = str(self._methodCombo.getSelectedItem())
            
            if not url:
                JOptionPane.showMessageDialog(self._mainPanel,
                    "Please enter a URL first", 
                    "No URL", JOptionPane.WARNING_MESSAGE)
                return
            
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
            else:
                JOptionPane.showMessageDialog(self._mainPanel,
                    "Error building request. Please check URL and parameters.", 
                    "Request Error", JOptionPane.ERROR_MESSAGE)
        except Exception as e:
            self._callbacks.printError("Error in _sendToRepeater: " + str(e))
    
    def _sendToIntruder(self):
        """Send current request to Intruder"""
        # Check if we have at least a URL and method
        url = self._requestUrlField.getText().strip()
        method = str(self._methodCombo.getSelectedItem())
        
        if not url:
            JOptionPane.showMessageDialog(self._mainPanel,
                "Please enter a URL first", 
                "No URL", JOptionPane.WARNING_MESSAGE)
            return
        
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
        else:
            JOptionPane.showMessageDialog(self._mainPanel,
                "Error building request. Please check URL and parameters.", 
                "Request Error", JOptionPane.ERROR_MESSAGE)
    
    def _sendToScanner(self):
        """Send current request to Scanner"""
        try:
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
            else:
                JOptionPane.showMessageDialog(self._mainPanel,
                    "Error building request. Please check URL and parameters.", 
                    "Request Error", JOptionPane.ERROR_MESSAGE)
        except Exception as e:
            self._callbacks.printError("Error in _sendToScanner: " + str(e))
    
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
    
    def _copyUrl(self):
        """Copy current URL to clipboard"""
        try:
            url = self._requestUrlField.getText()
            if url:
                # Use Java clipboard
                from java.awt import Toolkit
                from java.awt.datatransfer import StringSelection, Clipboard
                
                toolkit = Toolkit.getDefaultToolkit()
                clipboard = toolkit.getSystemClipboard()
                selection = StringSelection(url)
                clipboard.setContents(selection, selection)
                
                self._callbacks.printOutput("URL copied to clipboard: " + url)
                JOptionPane.showMessageDialog(self._mainPanel,
                    "URL copied to clipboard", 
                    "Success", JOptionPane.INFORMATION_MESSAGE)
            else:
                JOptionPane.showMessageDialog(self._mainPanel,
                    "No URL to copy", 
                    "Info", JOptionPane.INFORMATION_MESSAGE)
        except Exception as e:
            self._callbacks.printError("Error copying URL: " + str(e))
    
    def _copyMethod(self):
        """Copy current HTTP method to clipboard"""
        try:
            method = str(self._methodCombo.getSelectedItem())
            if method:
                # Use Java clipboard
                from java.awt import Toolkit
                from java.awt.datatransfer import StringSelection, Clipboard
                
                toolkit = Toolkit.getDefaultToolkit()
                clipboard = toolkit.getSystemClipboard()
                selection = StringSelection(method)
                clipboard.setContents(selection, selection)
                
                self._callbacks.printOutput("HTTP method copied to clipboard: " + method)
                JOptionPane.showMessageDialog(self._mainPanel,
                    "HTTP method copied to clipboard", 
                    "Success", JOptionPane.INFORMATION_MESSAGE)
            else:
                JOptionPane.showMessageDialog(self._mainPanel,
                    "No HTTP method to copy", 
                    "Info", JOptionPane.INFORMATION_MESSAGE)
        except Exception as e:
            self._callbacks.printError("Error copying HTTP method: " + str(e))
    
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
