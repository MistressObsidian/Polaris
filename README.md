# Base Banking Platform

> A modern digital banking platform with secure money transfers, real-time transaction tracking, and comprehensive financial management.

## ✨ Features

- **🔐 Secure Authentication** - User login and registration with session management
- **💳 Digital Home** - Real-time balance tracking and financial overview
- **💸 Money Transfers** - Send and receive transfers with transaction references
- **📊 Transaction History** - Detailed transaction records and status tracking
- **🔔 Webhook Integration** - Real-time notifications for transaction updates
- **🌐 Multi-Platform Sync** - Data synchronization across devices via SheetDB
- **📱 Responsive Design** - Mobile-friendly interface with modern UI

## 🛠️ Tech Stack

- **Frontend**: Vanilla HTML5, CSS3, JavaScript (ES6+)
- **Backend**: Node.js + Express.js
- **Database**: SQLite (local) + SheetDB (cloud sync)
- **Styling**: CSS Custom Properties, Gradient Animations
- **Testing**: Cypress (E2E testing)
- **Development**: Hot reload with http-server

## 🚀 Quick Start

### Prerequisites

- Node.js 16+ installed
- npm or yarn package manager

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/MistressObsidian/Banking.git
   cd Banking
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Set up environment variables**
   ```bash
   cp .env.example .env
   ```
   Edit `.env` with your configuration:
   ```env
   API_TOKEN=your-secure-api-token
   WEBHOOK_SECRET=your-webhook-secret
   WEBHOOK_TARGET=https://your-webhook-endpoint.com
   PORT=3001
   ```

4. **Start the development server**
   ```bash
   # Start API server (Terminal 1)
   npm run api
   
   # Start frontend server (Terminal 2) 
   npm run serve
   ```

5. **Access the application**
   - Frontend: https://polaris-uru5.onrender.com
   - API: https://polaris-uru5.onrender.com/api
   - Health check: https://polaris-uru5.onrender.com/api/health

## ☁️ Cloudflare Worker Routing

For Cloudflare proxy deployments, use same-origin API calls from the frontend and route only API paths through the Worker.

- Frontend config: `window.API_BASE = window.location.origin`
- Frontend requests: `fetch('/api/...')`
- Worker route: `Shenzhenswift.online/api/*`
- Do **not** set Worker route to `polaris-uru5.onrender.com/api/*`

## 📜 Available Scripts

- `npm run api` - Start the Express API server on port 3001
- `npm run serve` - Start the frontend server on port 5173  
- `npm run dev` - Start both servers concurrently (Windows PowerShell)
- `npm run test` - Open Cypress test runner
- `npm run test:headless` - Run tests in headless mode

## 📁 Project Structure

```
Banking/
├── 📄 Frontend Pages
│   ├── index.html              # Landing page
│   ├── login.html              # User authentication
│   ├── register.html           # User registration
│   ├── dashboard.html          # Financial home
│   ├── transfer.html           # Money transfer interface
│   ├── transaction-details.html # Transaction history
│   └── webhook-receiver.html   # Webhook notification handler
├── 🚀 Backend & Core
│   ├── server.js               # Express API server
│   ├── common.js               # Shared platform utilities
│   └── package.json            # Dependencies and scripts
├── 🧪 Testing
│   ├── cypress.config.js       # Cypress configuration
│   └── cypress/e2e/           # End-to-end tests
├── 📊 Data & Config
│   ├── data/                   # SQLite database storage
│   ├── .env.example           # Environment template
│   └── .gitignore             # Git ignore rules
└── 📚 Documentation
    └── docs/                   # Project documentation
```

### Proposed Future Structure
*Following future refactoring (Phase 2-3):*

```
Banking/
├── public/                     # Static frontend assets
│   ├── css/                   # Stylesheets with design tokens
│   ├── js/                    # Modular JavaScript components  
│   └── pages/                 # HTML templates
├── src/                       # Backend source code
│   ├── api/                   # API route handlers
│   ├── models/                # Data models and DB schema
│   └── utils/                 # Shared utilities
└── tests/                     # All test files
```

## 🗺️ Development Roadmap

### Phase 1: Foundation & Documentation ✅
- [x] Project documentation and setup guides
- [x] Code formatting and development standards
- [x] Contributing guidelines and community standards

### Phase 2: UI Design System 🚧
- [ ] Implement comprehensive design tokens (CSS custom properties)
- [ ] Create reusable component library
- [ ] Standardize typography, spacing, and color systems
- [ ] Add dark/light theme support

### Phase 3: Code Architecture 🔄
- [ ] Refactor `common.js` into modular ES6 components
- [ ] Implement proper API client layer with error handling
- [ ] Add client-side routing for SPA experience
- [ ] Organize assets into logical folder structure

### Phase 4: Accessibility & Performance ⚡
- [ ] WCAG 2.1 AA compliance audit and fixes
- [ ] Performance optimization (lazy loading, caching)
- [ ] SEO improvements and meta tags
- [ ] Progressive Web App (PWA) features

### Phase 5: Test Coverage 🧪
- [ ] Comprehensive Cypress E2E test suite
- [ ] Unit tests for critical business logic
- [ ] API integration tests
- [ ] Cross-browser compatibility testing

### Phase 6: Advanced Features 🚀
- [ ] Advanced theming and customization
- [ ] Micro-interactions and animations
- [ ] Real-time notifications (WebSocket/SSE)
- [ ] Mobile-first responsive enhancements

## 🔐 Security

This platform handles financial data. Please follow responsible disclosure:

- **Report security issues** to the maintainers privately
- **Do not** publicly disclose vulnerabilities before fixes are deployed
- Use environment variables for all sensitive configuration
- API tokens and secrets should never be committed to the repository

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

We welcome contributions! Please read our [Contributing Guidelines](CONTRIBUTING.md) and [Code of Conduct](CODE_OF_CONDUCT.md) before submitting pull requests.

## 📞 Support

- 📋 [Open an issue](https://github.com/MistressObsidian/Banking/issues) for bug reports
- 💡 [Request features](https://github.com/MistressObsidian/Banking/issues/new?template=feature_request.md)
- 📖 Check the [documentation](docs/) for detailed guides

---

<p align="center">
  <strong>Built with ❤️ for modern digital banking</strong>
</p>