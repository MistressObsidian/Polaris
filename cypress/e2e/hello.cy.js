describe('My First Test', () => {
    it('Visits the application', () => {
        cy.visit('/');
    cy.title().should('include', 'Bank Swift');
    });
});