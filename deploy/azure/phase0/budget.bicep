// Subscription-scope spend alerts (Phase 0 guardrail). Notifies; it does not stop spend.
targetScope = 'subscription'

@description('Budget amount in USD for the period (e.g. the free-credit size).')
@minValue(1)
param amountUsd int

@description('Alert recipient.')
param contactEmail string

@description('yyyy-MM-01 of the first month the budget covers.')
param startDate string

@allowed(['Monthly', 'Quarterly', 'Annually'])
param timeGrain string = 'Monthly'

resource budget 'Microsoft.Consumption/budgets@2023-11-01' = {
  name: 'aegis-phase0-budget'
  properties: {
    category: 'Cost'
    amount: amountUsd
    timeGrain: timeGrain
    timePeriod: { startDate: startDate }
    notifications: {
      actual50: { enabled: true, operator: 'GreaterThan', threshold: 50, contactEmails: [contactEmail], thresholdType: 'Actual' }
      actual80: { enabled: true, operator: 'GreaterThan', threshold: 80, contactEmails: [contactEmail], thresholdType: 'Actual' }
      actual95: { enabled: true, operator: 'GreaterThan', threshold: 95, contactEmails: [contactEmail], thresholdType: 'Actual' }
      forecast100: { enabled: true, operator: 'GreaterThan', threshold: 100, contactEmails: [contactEmail], thresholdType: 'Forecasted' }
    }
  }
}
