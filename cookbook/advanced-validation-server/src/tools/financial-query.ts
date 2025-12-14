/**
 * Financial Query Tool
 *
 * Demonstrates PII detection in responses.
 * Returns mock financial data that may contain sensitive information.
 */

import { z } from 'zod';

export const financialQuerySchema = z.object({
  query: z.enum(['customer-info', 'transaction-history', 'account-balance', 'safe-summary']),
  customerId: z.string().min(1).max(50)
});

export type FinancialQueryArgs = z.infer<typeof financialQuerySchema>;

// Mock customer database with intentionally sensitive data
const MOCK_CUSTOMERS: Record<string, unknown> = {
  'cust-001': {
    name: 'John Smith',
    email: 'john.smith@example.com',
    phone: '(555) 123-4567',
    ssn: '123-45-6789',
    accounts: [
      { type: 'checking', balance: 5432.10, lastFour: '4532' },
      { type: 'savings', balance: 15000.00, lastFour: '7891' }
    ],
    creditCard: '4532-1234-5678-9012'
  },
  'cust-002': {
    name: 'Jane Doe',
    email: 'jane.doe@company.org',
    phone: '+1 555-987-6543',
    ssn: '987-65-4321',
    accounts: [
      { type: 'checking', balance: 2500.00, lastFour: '1234' }
    ],
    creditCard: '5432 8765 4321 0987'
  },
  'cust-003': {
    name: 'Safe Customer',
    memberSince: '2020-01-15',
    accountStatus: 'active',
    tier: 'gold'
  }
};

export async function handleFinancialQuery(args: FinancialQueryArgs) {
  const customer = MOCK_CUSTOMERS[args.customerId];

  if (!customer) {
    return {
      content: [{
        type: 'text' as const,
        text: JSON.stringify({ error: 'Customer not found', customerId: args.customerId }, null, 2)
      }]
    };
  }

  let result: unknown;

  switch (args.query) {
    case 'customer-info':
      // Returns full customer info including PII
      result = customer;
      break;

    case 'transaction-history':
      // Returns transaction history with card numbers
      result = {
        customerId: args.customerId,
        transactions: [
          { date: '2024-01-15', amount: -125.50, merchant: 'Amazon', card: '****9012' },
          { date: '2024-01-14', amount: -45.00, merchant: 'Gas Station', card: '****9012' },
          { date: '2024-01-13', amount: 2500.00, merchant: 'Direct Deposit', type: 'credit' }
        ]
      };
      break;

    case 'account-balance':
      // Returns balances (less sensitive)
      result = {
        customerId: args.customerId,
        totalBalance: 20432.10,
        accounts: [
          { type: 'checking', available: 5432.10 },
          { type: 'savings', available: 15000.00 }
        ]
      };
      break;

    case 'safe-summary':
      // Returns only non-PII data
      result = {
        customerId: args.customerId,
        accountStatus: 'active',
        tier: 'premium',
        lastActivity: '2024-01-15'
      };
      break;
  }

  return {
    content: [{
      type: 'text' as const,
      text: JSON.stringify(result, null, 2)
    }]
  };
}
