# Financial Extraction - Quick Reference Guide

## Supported Metrics (13 Total)

### Income Statement (5)
```
'revenue'              → Total revenues, net revenues, sales
'gross_profit'         → Cost of revenue, gross margin
'operating_income'     → Operating profit, EBIT
'net_income'           → Net earnings, profit for period
'eps_diluted'          → Earnings per share (diluted)
```

### Cash Flow (3)
```
'operating_cash_flow'  → Cash from operations, OCF
'capital_expenditure'  → CapEx, PP&E purchases
'free_cash_flow'       → OCF - CapEx
```

### Balance Sheet (5)
```
'total_assets'         → All assets
'current_assets'       → Liquid assets
'total_liabilities'    → All liabilities
'current_liabilities'  → Short-term liabilities
'stockholder_equity'   → Shareholders' equity
```

## Filing Types Supported

| Type | Code | Available Metrics |
|------|------|-------------------|
| Annual (US) | 10-K | All 13 |
| Quarterly (US) | 10-Q | 5 (no balance sheet) |
| Current Report | 8-K | 2 (revenue, net income) |
| Annual (Int'l) | 20-F | All 13 |
| Quarterly (Int'l) | 20-Q | 5 |
| Registration | S-1/S-4 | 2 |
| Proxy | DEF 14A | 0 (no financials) |

## API Usage

### Extract Single Metric
```javascript
const result = extractFinancialMetric(text, 'operating_income');
// {
//   value: 109400,
//   raw: "109,400",
//   metric: "operating_income",
//   unit: "millions"
// }
```

### Detect Filing Type
```javascript
const type = detectFilingType(text, '10-K');
// "annual"
```

### Get Metrics for Filing
```javascript
const metrics = getMetricsForFilingType('quarterly');
// ["revenue", "operating_income", "net_income", "operating_cash_flow", "eps_diluted"]
```

### Find Statement Section
```javascript
const section = findFinancialStatementSection(text, 'consolidated\\s+income', '10-K');
// Returns 40,000 character excerpt with income statement
```

## Pattern Examples

### Revenue
Matches: "Total Revenues: $245,100", "Net revenues $245,100", "2024: $245,100", "Sales: $245,100"

### Operating Income
Matches: "Operating Income: $109,400", "Income from Operations", "Operating Profit", "EBIT: $109,400"

### Cash Flow
Matches: "Net cash from operating activities", "Cash from operations", "Operating cash flow: $118,500"

### Assets
Matches: "Total Assets: $512,200", "Current Assets: $250,000"

## Validation Rules

All extracted values are validated:

```javascript
{
  value >= minValue &&
  value <= maxValue
}
```

**Examples:**
- Revenue: 0 ≤ value ≤ 1,000,000M
- Net Income: -1,000,000M ≤ value ≤ 1,000,000M
- CapEx: 0 ≤ value ≤ 1,000,000M
- EPS: -1,000 ≤ value ≤ 1,000
```

## Common Issues & Solutions

### Issue: "No valid match for operating_income"
**Solution**: Filing may not include this metric
- Check filing type (8-K has limited metrics)
- Verify metric is in `getMetricsForFilingType()` for that type
- Check server logs for pattern failures

### Issue: Value outside valid range
**Solution**: Extracted value failed validation
- Check for unusual units (billions vs millions)
- Verify currency is standard ($)
- May indicate incorrect pattern match

### Issue: Revenue extraction failing
**Solution**: 
1. Check filing has income statement
2. Look for "Consolidated Statements of Operations"
3. Verify revenue line has dollar amount nearby
4. Check server logs for which patterns were tried

## Debugging

### Enable Detailed Logs
```bash
tail -f server.log | grep extractFinancialMetric
```

**Example Output:**
```
[extractFinancialMetric] operating_income: $109,400 (unit: millions)
[extractFinancialMetric] No valid match for gross_profit
[findFinancialStatement] Found income statement at position 52341 (10-K)
```

### Test Extraction Locally
```javascript
// In Node REPL:
const text = fs.readFileSync('filing.txt', 'utf-8');
extractFinancialMetric(text, 'revenue');
```

## Performance

- Per metric: 1-5ms
- All 13 metrics: 50-100ms
- Filing detection: <1ms
- Section finding: 5-20ms
- **Total overhead**: ~100-200ms per filing

## International Variations

### 20-F Filings (IFRS)
- "Revenue" → also try "Turnover", "Net sales"
- "Operating Income" → "Operating profit"
- "Net Income" → "Profit for the period"
- Currencies: €, £, ¥ supported
- Units: millions, thousands both handled

### Currency Support
- USD ($) ✓
- EUR (€) ✓
- GBP (£) ✓
- JPY (¥) ✓
- INR (₹) ✓

## Best Practices

1. **Always detect filing type first**
   ```javascript
   const type = detectFilingType(text, formType);
   const availableMetrics = getMetricsForFilingType(type);
   ```

2. **Check if metric is available**
   ```javascript
   if (availableMetrics.includes('gross_profit')) {
     const data = extractFinancialMetric(text, 'gross_profit');
   }
   ```

3. **Handle null results gracefully**
   ```javascript
   const result = extractFinancialMetric(text, 'operating_income');
   const value = result?.value || 'Not available';
   ```

4. **Log failures for monitoring**
   ```javascript
   if (!result) {
     console.warn(`Failed to extract ${metric} from ${formType}`);
   }
   ```

5. **Validate extracted values**
   ```javascript
   if (result && result.value > 0) {
     // Use the value
   }
   ```

## Adding New Metrics

To add a new metric like "EBITDA":

1. Add to `metrics` object:
```javascript
'ebitda': {
  patterns: [
    /ebitda[\s:=]*\$?\s*\(?([0-9,]+)/i,
    /earnings?\s+before\s+interest[\s,]+taxes[\s,]+(?:depreciation|amortization)[\s:=]*\$?\s*\(?([0-9,]+)/i
  ],
  minValue: -1000000,
  maxValue: 1000000,
  unit: 'millions'
}
```

2. Add to relevant filing types in `getMetricsForFilingType()`:
```javascript
'annual': [..., 'ebitda']
'quarterly': [..., 'ebitda']
```

3. Test with 5+ companies

## Troubleshooting Checklist

- [ ] Filing type detected correctly?
- [ ] Metric available in this filing type?
- [ ] Is extracted value in valid range?
- [ ] Does value match IR data ±5%?
- [ ] Check server logs for pattern matches?
- [ ] Try different company for verification?

---

**Version**: 1.0  
**Last Updated**: 2026-06-28  
**Status**: Production Ready ✓
