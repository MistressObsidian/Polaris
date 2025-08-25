describe('My First Test', () => {
    it('Visits the application', () => {
        cy.visit('/');
        cy.contains('Welcome'); // Adjust the text based on your application
    });
});