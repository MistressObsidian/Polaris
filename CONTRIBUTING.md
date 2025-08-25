# Contributing to Bank Swift Banking Platform

Thank you for your interest in contributing to our digital banking platform! This guide will help you get started with making meaningful contributions.

## 🚀 Getting Started

### Prerequisites

- Node.js 16+ installed
- Git configured with your GitHub account
- Basic knowledge of HTML, CSS, JavaScript, and Node.js
- Understanding of banking/financial concepts (helpful but not required)

### Development Setup

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/Banking.git
   cd Banking
   ```
3. Add the original repository as upstream:
   ```bash
   git remote add upstream https://github.com/MistressObsidian/Banking.git
   ```
4. Install dependencies:
   ```bash
   npm install
   ```
5. Copy environment configuration:
   ```bash
   cp .env.example .env
   ```
6. Start development servers:
   ```bash
   npm run api    # Terminal 1
   npm run serve  # Terminal 2
   ```

## 📋 Development Workflow

### Branch Naming Convention

Use clear, descriptive branch names with prefixes:

- `feature/add-transaction-search` - New features
- `fix/dashboard-balance-display` - Bug fixes  
- `chore/update-dependencies` - Maintenance tasks
- `docs/api-documentation` - Documentation updates
- `refactor/modular-js-components` - Code restructuring
- `style/responsive-mobile-layout` - UI/UX improvements

### Commit Message Format

We follow [Conventional Commits](https://conventionalcommits.org/) for clear commit history:

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

**Types:**
- `feat`: New feature implementation
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code formatting, whitespace (not UI changes)
- `refactor`: Code restructuring without functional changes
- `test`: Adding or updating tests
- `chore`: Maintenance tasks, dependency updates

**Examples:**
```bash
git commit -m "feat(dashboard): add real-time balance updates"
git commit -m "fix(transfer): resolve amount validation error"
git commit -m "docs(readme): update installation instructions"
git commit -m "refactor(common): extract API client to separate module"
```

## 🔧 Code Standards

### JavaScript Guidelines

- Use ES6+ features (const/let, arrow functions, async/await)
- Prefer functional programming patterns where appropriate
- Add JSDoc comments for complex functions
- Handle errors gracefully with try/catch blocks
- Use meaningful variable and function names

```javascript
// Good
const calculateAvailableBalance = async (userId) => {
  try {
    const user = await fetchUserData(userId);
    return user.totalBalance - user.pendingTransactions;
  } catch (error) {
    console.error('Balance calculation failed:', error);
    return 0;
  }
};

// Avoid
function calc(u) {
  return u.bal - u.pend;
}
```

### HTML/CSS Guidelines

- Use semantic HTML elements (`<main>`, `<section>`, `<article>`)
- Ensure accessibility with ARIA labels and proper focus management
- Use CSS custom properties (variables) for consistent theming
- Mobile-first responsive design approach
- Keep CSS organized with logical grouping and comments

```css
/* Good - Using CSS custom properties */
.dashboard-card {
  background: var(--card-background);
  border: 1px solid var(--border-color);
  border-radius: var(--border-radius-md);
  padding: var(--spacing-lg);
}

/* Avoid - Hard-coded values */
.card {
  background: #ffffff;
  border: 1px solid #e5e7eb;
  border-radius: 8px;
  padding: 24px;
}
```

### Code Formatting

We use Prettier for consistent code formatting. Before committing:

```bash
# Format all files (when Prettier is configured)
npm run format

# Or manually format key files
prettier --write "*.{js,html,css,json,md}"
```

## 🧪 Testing Requirements

### Before Submitting a PR

- [ ] All existing tests pass locally
- [ ] New features include appropriate test coverage
- [ ] Manual testing completed on key user flows
- [ ] Cross-browser testing (Chrome, Firefox, Safari)
- [ ] Mobile responsiveness verified

### Test Types

1. **Manual Testing**: Always test your changes manually
2. **E2E Tests**: Use Cypress for user workflow testing
3. **Unit Tests**: For utility functions and business logic
4. **Integration Tests**: For API endpoints and data flow

```bash
# Run E2E tests
npm run test:headless

# Open interactive test runner  
npm run test
```

## 📝 Pull Request Process

### Before Creating a PR

1. **Sync with upstream**:
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. **Test thoroughly**:
   ```bash
   npm run api & npm run serve  # Test locally
   npm run test:headless       # Run automated tests
   ```

3. **Commit and push**:
   ```bash
   git add .
   git commit -m "feat(scope): description"
   git push origin your-branch-name
   ```

### PR Template Checklist

When opening a pull request, ensure:

- [ ] **Clear title** describing the change
- [ ] **Detailed description** explaining what and why
- [ ] **Screenshots/videos** for UI changes
- [ ] **Tests added/updated** for new functionality
- [ ] **Documentation updated** if needed
- [ ] **Backward compatibility** considered
- [ ] **Performance impact** assessed
- [ ] **Security implications** reviewed

### PR Description Template

```markdown
## 🎯 Purpose
Brief description of what this PR accomplishes.

## 🔄 Changes Made
- List key changes
- Include technical details
- Reference related issues

## 🧪 Testing
- [ ] Manual testing completed
- [ ] E2E tests pass
- [ ] Cross-browser testing done
- [ ] Mobile responsiveness verified

## 📸 Screenshots/Videos
Include before/after screenshots for UI changes.

## 📋 Additional Notes
Any special considerations, deployment notes, or follow-up tasks.

Fixes #123
```

## 🏷️ Issue Labels and Workflow

### Issue Types

- `enhancement` - New feature requests
- `bug` - Bug reports and fixes
- `documentation` - Documentation improvements
- `design` - UI/UX enhancements
- `a11y` - Accessibility improvements
- `performance` - Performance optimizations
- `security` - Security-related issues
- `good-first-issue` - Beginner-friendly tasks
- `help-wanted` - Issues needing contributor assistance

### Priority Levels

- `priority/critical` - Security vulnerabilities, data loss risks
- `priority/high` - Major functionality broken
- `priority/medium` - Important improvements
- `priority/low` - Nice-to-have enhancements

## 🎨 Design and UI Contributions

### Design System Guidelines

We're building a comprehensive design system. When contributing UI changes:

1. **Use existing design tokens** (CSS custom properties)
2. **Follow spacing and typography scales**
3. **Maintain consistent component patterns**
4. **Consider dark mode compatibility**
5. **Test accessibility** (color contrast, keyboard navigation)

### UI Change Requirements

- Include before/after screenshots
- Test on multiple screen sizes (320px to 1920px+)
- Verify color contrast ratios meet WCAG AA standards
- Test keyboard navigation and screen reader compatibility

## 🚨 Security Considerations

When working with financial data:

- Never commit API tokens, secrets, or credentials
- Use environment variables for sensitive configuration
- Validate and sanitize all user inputs
- Follow secure coding practices for authentication
- Report security vulnerabilities privately to maintainers

## 📚 Resources

### Documentation

- [Project Architecture](docs/ARCHITECTURE_OVERVIEW.md)
- [Development Roadmap](docs/ROADMAP.md)
- [Design Tokens Plan](docs/DESIGN_TOKENS_PLAN.md)

### Learning Resources

- [MDN Web Docs](https://developer.mozilla.org/) - Web development reference
- [Node.js Documentation](https://nodejs.org/docs/) - Server-side JavaScript
- [Express.js Guide](https://expressjs.com/) - Web framework
- [Cypress Documentation](https://docs.cypress.io/) - E2E testing

## ❓ Getting Help

- 💬 **Discussions**: Use GitHub Discussions for questions and ideas
- 🐛 **Issues**: Report bugs or request features via GitHub Issues  
- 📧 **Direct Contact**: Reach out to maintainers for sensitive matters
- 🔍 **Code Review**: Don't hesitate to ask for early feedback on drafts

## 🌟 Recognition

Contributors will be recognized in:
- GitHub contributors list
- Release notes for significant contributions
- Project documentation credits

Thank you for helping make Bank Swift Banking Platform better! 🚀

---

*This contributing guide is a living document. Please suggest improvements via pull requests.*