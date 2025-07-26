import React, { useState, useRef } from 'react';
import { Upload, MessageCircle, FileText, Shield, Zap, Brain, Lock, Search, Send, AlertTriangle, CheckCircle, Code, FileCode, FolderOpen } from 'lucide-react';

const PrybarApp = () => {
  const [files, setFiles] = useState([]);
  const [messages, setMessages] = useState([]);
  const [inputMessage, setInputMessage] = useState('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [currentView, setCurrentView] = useState('upload'); // 'upload', 'chat', 'results'
  const [selectedFile, setSelectedFile] = useState(null);
  const fileInputRef = useRef(null);

  // Sample vulnerabilities for demo
  const sampleVulnerabilities = [
    {
      type: 'SQL Injection',
      severity: 'High',
      file: 'auth.py',
      line: 45,
      description: 'User input is directly concatenated into SQL query without sanitization',
      code: `cursor.execute("SELECT * FROM users WHERE username = '" + username + "'")`
    },
    {
      type: 'Hardcoded Password',
      severity: 'Critical',
      file: 'config.py',
      line: 12,
      description: 'Database password is hardcoded in source code',
      code: `DB_PASSWORD = "admin123"`
    },
    {
      type: 'XSS Vulnerability',
      severity: 'Medium',
      file: 'templates/dashboard.html',
      line: 28,
      description: 'User input rendered without escaping',
      code: `<div>Welcome {user.name}</div>`
    }
  ];

  const handleFileUpload = (event) => {
    const uploadedFiles = Array.from(event.target.files);
    const processedFiles = uploadedFiles.map(file => ({
      name: file.name,
      size: file.size,
      type: file.type,
      content: null // In real app, would read file content
    }));
    setFiles(processedFiles);
    if (uploadedFiles.length > 0) {
      setCurrentView('chat');
    }
  };

  const handleDragOver = (e) => {
    e.preventDefault();
  };

  const handleDrop = (e) => {
    e.preventDefault();
    const droppedFiles = Array.from(e.dataTransfer.files);
    const processedFiles = droppedFiles.map(file => ({
      name: file.name,
      size: file.size,
      type: file.type,
      content: null
    }));
    setFiles(processedFiles);
    if (droppedFiles.length > 0) {
      setCurrentView('chat');
    }
  };

  const simulateAIResponse = (question) => {
    const responses = {
      'sql injection': {
        text: "I found a potential SQL injection vulnerability in your code. In `auth.py` at line 45, you're directly concatenating user input into a SQL query without sanitization. This allows attackers to manipulate your database queries by injecting malicious SQL code through the username parameter.",
        code: `# Vulnerable code:
cursor.execute("SELECT * FROM users WHERE username = '" + username + "'")

# Secure alternative using parameterized queries:
cursor.execute("SELECT * FROM users WHERE username = %s", (username,))

# Or using prepared statements:
stmt = "SELECT * FROM users WHERE username = ?"
cursor.execute(stmt, (username,))`,
        severity: 'High',
        file: 'auth.py',
        line: 45
      },
      'hardcoded': {
        text: "Yes, I found hardcoded credentials in your `config.py` file. On line 12, you have a database password directly in the source code. This is a critical security risk as anyone with access to your code repository can see these credentials. Additionally, if this code is deployed to version control, the password history will be permanently stored.",
        code: `# Vulnerable:
DB_PASSWORD = "admin123"

# Secure alternatives:
# 1. Environment variables
DB_PASSWORD = os.getenv('DB_PASSWORD')

# 2. Configuration file (not in version control)
import configparser
config = configparser.ConfigParser()
config.read('secrets.ini')
DB_PASSWORD = config['database']['password']

# 3. Secret management service
from azure.keyvault.secrets import SecretClient
DB_PASSWORD = secret_client.get_secret("db-password").value`,
        severity: 'Critical',
        file: 'config.py',
        line: 12
      },
      'input sanitization': {
        text: "I can see several areas where user input isn't properly sanitized. The main issues are in your authentication system and form handlers. You should validate and escape all user inputs before processing them to prevent injection attacks and XSS vulnerabilities.",
        code: `# Add comprehensive input validation:
import re
from html import escape
import bleach

def sanitize_input(user_input, input_type='text'):
    if not user_input:
        return ''
    
    # Remove null bytes and control characters
    cleaned = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x84\x86-\x9f]', '', user_input)
    
    if input_type == 'html':
        # For HTML content, use bleach to allow safe tags
        allowed_tags = ['p', 'br', 'strong', 'em']
        cleaned = bleach.clean(cleaned, tags=allowed_tags, strip=True)
    else:
        # For regular text, escape HTML entities
        cleaned = escape(cleaned)
    
    return cleaned.strip()

# Example usage:
username = sanitize_input(request.form.get('username'))
comment = sanitize_input(request.form.get('comment'), 'html')`,
        severity: 'Medium',
        file: 'Multiple files',
        line: 'Various'
      },
      'xss': {
        text: "I found potential XSS (Cross-Site Scripting) vulnerabilities in your template files. In `templates/dashboard.html` at line 28, you're rendering user input directly without escaping. This allows attackers to inject malicious JavaScript that will execute in other users' browsers.",
        code: `<!-- Vulnerable template: -->
<div>Welcome {user.name}</div>

<!-- Secure alternatives: -->
<!-- 1. Auto-escaping (most template engines) -->
<div>Welcome {{ user.name|e }}</div>

<!-- 2. Manual escaping in Python -->
from html import escape
safe_name = escape(user.name)

<!-- 3. Using template filters -->
<div>Welcome {{ user.name|escape }}</div>

<!-- 4. For trusted HTML content -->
<div>Welcome {{ user.name|safe }}</div>  <!-- Only if you trust the content -->`,
        severity: 'Medium',
        file: 'templates/dashboard.html',
        line: 28
      },
      'default': {
        text: "I've analyzed your codebase and found several potential security issues. The most critical ones involve SQL injection vulnerabilities in your authentication system and hardcoded credentials in your configuration files. I also noticed some input sanitization issues that could lead to XSS attacks. Would you like me to explain any specific vulnerability in detail?",
        code: `# Security summary for your codebase:
# 1. SQL Injection (High) - auth.py:45
# 2. Hardcoded credentials (Critical) - config.py:12  
# 3. XSS vulnerability (Medium) - templates/dashboard.html:28
# 4. Missing input validation (Medium) - Multiple files

# Recommended immediate actions:
# - Replace string concatenation with parameterized queries
# - Move secrets to environment variables
# - Implement proper input sanitization
# - Add output encoding for all user data in templates`,
        severity: 'Mixed',
        file: 'Multiple files',
        line: 'Various'
      }
    };

    const lowerQuestion = question.toLowerCase();
    let response = responses.default;
    
    if (lowerQuestion.includes('sql') || lowerQuestion.includes('injection')) {
      response = responses['sql injection'];
    } else if (lowerQuestion.includes('hardcoded') || lowerQuestion.includes('password')) {
      response = responses['hardcoded'];
    } else if (lowerQuestion.includes('sanitiz') || lowerQuestion.includes('input')) {
      response = responses['input sanitization'];
    } else if (lowerQuestion.includes('xss') || lowerQuestion.includes('cross-site')) {
      response = responses['xss'];
    }

    return response;
  };

  const handleSendMessage = (message = null) => {
    const messageToSend = message || inputMessage;
    if (!messageToSend.trim()) return;

    const userMessage = {
      type: 'user',
      content: messageToSend,
      timestamp: new Date()
    };

    setMessages(prev => [...prev, userMessage]);
    setIsAnalyzing(true);
    setInputMessage(''); // Clear input immediately

    // Simulate AI processing
    setTimeout(() => {
      const aiResponse = simulateAIResponse(messageToSend);
      const aiMessage = {
        type: 'ai',
        content: aiResponse.text,
        code: aiResponse.code,
        severity: aiResponse.severity,
        file: aiResponse.file,
        line: aiResponse.line,
        timestamp: new Date()
      };

      setMessages(prev => [...prev, aiMessage]);
      setIsAnalyzing(false);
    }, 2000);
  };

  const handleQuickQuestion = (question) => {
    setInputMessage(question);
    handleSendMessage(question);
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'Critical': return 'text-red-600 bg-red-100';
      case 'High': return 'text-orange-600 bg-orange-100';
      case 'Medium': return 'text-yellow-600 bg-yellow-100';
      case 'Low': return 'text-green-600 bg-green-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  const UploadView = () => (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100">
      {/* Header */}
      <div className="bg-white shadow-sm">
        <div className="max-w-7xl mx-auto px-4 py-6">
          <div className="flex items-center space-x-3">
            <div className="bg-indigo-600 p-2 rounded-lg">
              <Shield className="h-8 w-8 text-white" />
            </div>
            <div>
              <h1 className="text-3xl font-bold text-gray-900">Prybar</h1>
              <p className="text-gray-600">AI-Powered Security Code Analysis</p>
            </div>
          </div>
        </div>
      </div>

      {/* Main Content */}
      <div className="max-w-4xl mx-auto px-4 py-12">
        {/* Features Section */}
        <div className="text-center mb-12">
          <h2 className="text-4xl font-bold text-gray-900 mb-4">
            Secure Code Analysis Made Simple
          </h2>
          <p className="text-xl text-gray-600 mb-8">
            Upload your code and ask questions in plain English. Get clear, actionable security insights.
          </p>
          
          <div className="grid md:grid-cols-3 gap-8 mb-12">
            <div className="bg-white rounded-xl p-6 shadow-lg">
              <Brain className="h-12 w-12 text-indigo-600 mx-auto mb-4" />
              <h3 className="text-xl font-semibold mb-2">AI-Powered Analysis</h3>
              <p className="text-gray-600">Advanced AI understands your code and explains vulnerabilities in simple terms</p>
            </div>
            <div className="bg-white rounded-xl p-6 shadow-lg">
              <Lock className="h-12 w-12 text-indigo-600 mx-auto mb-4" />
              <h3 className="text-xl font-semibold mb-2">Privacy First</h3>
              <p className="text-gray-600">Your code stays on your machine. Offline-capable with local LLMs</p>
            </div>
            <div className="bg-white rounded-xl p-6 shadow-lg">
              <MessageCircle className="h-12 w-12 text-indigo-600 mx-auto mb-4" />
              <h3 className="text-xl font-semibold mb-2">Interactive Learning</h3>
              <p className="text-gray-600">Ask questions and get educational explanations, not just error lists</p>
            </div>
          </div>
        </div>

        {/* Upload Section */}
        <div className="bg-white rounded-2xl shadow-xl p-8">
          <h3 className="text-2xl font-bold text-gray-900 mb-6 text-center">
            Upload Your Code
          </h3>
          
          <div
            className="border-2 border-dashed border-gray-300 rounded-xl p-12 text-center hover:border-indigo-400 transition-colors cursor-pointer"
            onDragOver={handleDragOver}
            onDrop={handleDrop}
            onClick={() => fileInputRef.current?.click()}
          >
            <Upload className="h-16 w-16 text-gray-400 mx-auto mb-4" />
            <p className="text-xl text-gray-600 mb-2">
              Drag & drop your files here, or click to browse
            </p>
            <p className="text-gray-500">
              Supports .py, .js, .php, .java, .zip and more
            </p>
            <input
              ref={fileInputRef}
              type="file"
              multiple
              onChange={handleFileUpload}
              className="hidden"
              accept=".py,.js,.php,.java,.zip,.tar,.gz"
            />
          </div>

          {files.length > 0 && (
            <div className="mt-6">
              <h4 className="font-semibold text-gray-900 mb-3">Uploaded Files:</h4>
              <div className="space-y-2">
                {files.map((file, index) => (
                  <div key={index} className="flex items-center space-x-3 p-3 bg-gray-50 rounded-lg">
                    <FileCode className="h-5 w-5 text-indigo-600" />
                    <span className="font-medium">{file.name}</span>
                    <span className="text-sm text-gray-500">({(file.size / 1024).toFixed(1)} KB)</span>
                  </div>
                ))}
              </div>
              <button
                onClick={() => setCurrentView('chat')}
                className="mt-4 bg-indigo-600 text-white px-6 py-3 rounded-lg hover:bg-indigo-700 transition-colors font-medium"
              >
                Start Analysis
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );

 const ChatView = () => (
  <div className="min-h-screen bg-gray-50 flex flex-col">
    {/* Header */}
    <div className="bg-white shadow-sm border-b">
      <div className="max-w-7xl mx-auto px-4 py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="bg-indigo-600 p-2 rounded-lg">
              <Shield className="h-6 w-6 text-white" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-gray-900">Prybar Analysis</h1>
              <p className="text-sm text-gray-600">{files.length} files uploaded</p>
            </div>
          </div>
          <button
            onClick={() => setCurrentView('upload')}
            className="text-indigo-600 hover:text-indigo-700 font-medium"
          >
            Upload New Files
          </button>
        </div>
      </div>
    </div>

    {/* Main Section */}
    <div className="flex-1 max-w-6xl mx-auto w-full px-4 py-6 grid lg:grid-cols-4 gap-6">
      
      {/* Sidebar */}
      <div className="lg:col-span-1">
        <div className="bg-white rounded-lg shadow p-4 h-full flex flex-col">
          <h3 className="font-semibold text-gray-900 mb-3 flex items-center">
            <FolderOpen className="h-5 w-5 mr-2" />
            Project Files
          </h3>
          <div className="space-y-2">
            {files.map((file, index) => (
              <div
                key={index}
                className="flex items-center space-x-2 p-2 hover:bg-gray-50 rounded cursor-pointer"
                onClick={() => setSelectedFile(file)}
              >
                <FileCode className="h-4 w-4 text-gray-500" />
                <span className="text-sm text-gray-700">{file.name}</span>
              </div>
            ))}
          </div>

          <div className="mt-6 pt-4 border-t">
            <h4 className="text-sm font-medium text-gray-900 mb-3">Quick Questions</h4>
            <div className="space-y-2">
              {[
                'Are there any SQL injection vulnerabilities?',
                'Do I have hardcoded passwords?',
                'Is user input properly sanitized?',
                'Are there any XSS vulnerabilities?'
              ].map((question, index) => (
                <button
                  key={index}
                  onClick={() => handleQuickQuestion(question)}
                  disabled={isAnalyzing}
                  className="w-full text-left text-sm text-indigo-600 hover:text-indigo-700 hover:bg-indigo-50 p-2 rounded transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {question}
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Chat Area */}
      <div className="lg:col-span-3 flex flex-col h-[calc(100vh-10rem)]">
        <div className="bg-white rounded-lg shadow flex flex-col flex-1 overflow-hidden">
          
          {/* Messages */}
          <div className="flex-1 overflow-y-auto p-4 space-y-4">
            {messages.length === 0 && (
              <div className="text-center py-8">
                <MessageCircle className="h-12 w-12 text-gray-400 mx-auto mb-4" />
                <p className="text-gray-600">Ask me anything about your code security!</p>
                <p className="text-sm text-gray-500 mt-2">
                  Try: "Are there any vulnerabilities in my authentication code?"
                </p>
              </div>
            )}

            {messages.map((message, index) => (
              <div key={index} className={`flex ${message.type === 'user' ? 'justify-end' : 'justify-start'}`}>
                <div className={`max-w-3xl ${message.type === 'user' ? 'bg-indigo-600 text-white' : 'bg-gray-100'} rounded-lg p-4`}>
                  <p className="mb-2">{message.content}</p>
                  {message.code && (
                    <div className="mt-3 bg-gray-800 text-gray-200 p-3 rounded text-sm font-mono overflow-x-auto">
                      <pre>{message.code}</pre>
                    </div>
                  )}
                  {message.severity && (
                    <div className="mt-3 flex items-center space-x-4">
                      <span className={`px-2 py-1 rounded text-xs font-medium ${getSeverityColor(message.severity)}`}>
                        {message.severity}
                      </span>
                      <span className="text-xs text-gray-500">
                        {message.file}:{message.line}
                      </span>
                    </div>
                  )}
                </div>
              </div>
            ))}

            {isAnalyzing && (
              <div className="flex justify-start">
                <div className="bg-gray-100 rounded-lg p-4">
                  <div className="flex items-center space-x-2">
                    <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-indigo-600"></div>
                    <span>Analyzing your code...</span>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Input Box */}
          <div className="border-t p-4">
            <div className="flex space-x-2">
              <input
                type="text"
                value={inputMessage}
                onChange={(e) => setInputMessage(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleSendMessage()}
                placeholder="Ask about your code security..."
                className="flex-1 border rounded-lg px-4 py-2 focus:outline-none focus:ring-2 focus:ring-indigo-500"
                disabled={isAnalyzing}
              />
              <button
                onClick={() => handleSendMessage()}
                disabled={isAnalyzing || !inputMessage.trim()}
                className="bg-indigo-600 text-white px-4 py-2 rounded-lg hover:bg-indigo-700 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <Send className="h-5 w-5" />
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
);


  return (
    <div className="font-sans">
      {currentView === 'upload' ? <UploadView /> : <ChatView />}
    </div>
  );
};

export default PrybarApp;