describe('My First Test', () => {
    it('Visits the application', () => {
        cy.visit('http://localhost:3000');
        cy.contains('Welcome'); // Adjust the text based on your application
    });
});