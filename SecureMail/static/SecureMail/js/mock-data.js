const mockEmails = [
  { 
    id: 1, 
    sender: 'Amazon Security', 
    email: 'security@amaz0n-verify.com', 
    subject: 'Urgent: Verify Your Account Now!', 
    preview: 'Your account has been compromised. Click here immediately to verify...', 
    date: '10:32 AM', 
    unread: true, 
    risk: 'dangerous', 
    score: 92, 
    hasAttachment: true, 
    body: 'Dear Customer,\n\nWe have detected unusual activity on your Amazon account. Your account will be suspended within 24 hours unless you verify your identity immediately.\n\nClick the link below to verify:\nhttps://amaz0n-verify.com/secure-login\n\nPlease provide your full name, credit card number, and social security number for verification.\n\nAmazon Security Team', 
    threats: [
      'Fake sender domain (amaz0n-verify.com)',
      'Urgency tactics',
      'Requests sensitive information',
      'Suspicious URL detected',
      'Domain mismatch with official Amazon'
    ] 
  },
  { 
    id: 2, 
    sender: 'John Smith', 
    email: 'john.smith@company.com', 
    subject: 'Q4 Budget Review Meeting', 
    preview: 'Hi team, please find attached the Q4 budget review presentation...', 
    date: '9:15 AM', 
    unread: true, 
    risk: 'safe', 
    score: 8, 
    hasAttachment: true, 
    body: 'Hi team,\n\nPlease find attached the Q4 budget review presentation for our meeting tomorrow at 2 PM.\n\nKey discussion points:\n- Revenue projections\n- Cost optimization\n- Hiring plans\n\nLet me know if you have any questions.\n\nBest,\nJohn', 
    threats: [] 
  },
  { 
    id: 3, 
    sender: 'Netflix', 
    email: 'billing@netflix-renew.net', 
    subject: 'Payment Failed - Update Now', 
    preview: 'Your Netflix subscription payment has failed. Update your payment method...', 
    date: 'Yesterday', 
    unread: false, 
    risk: 'suspicious', 
    score: 67, 
    hasAttachment: false, 
    body: 'Hello,\n\nWe were unable to process your monthly payment for your Netflix subscription. Please update your payment information within 48 hours to avoid service interruption.\n\nUpdate Payment: https://netflix-renew.net/billing\n\nNetflix Billing Team', 
    threats: [
      'Unofficial domain (netflix-renew.net)',
      'Payment urgency tactic',
      'Suspicious link detected'
    ] 
  },
  { 
    id: 4, 
    sender: 'Sarah Johnson', 
    email: 'sarah.j@gmail.com', 
    subject: 'Weekend BBQ Plans', 
    preview: 'Hey! Are you free this Saturday for a BBQ at our place?...', 
    date: 'Yesterday', 
    unread: false, 
    risk: 'safe', 
    score: 3, 
    hasAttachment: false, 
    body: 'Hey!\n\nAre you free this Saturday for a BBQ at our place? We\'re thinking around 4 PM. Bring the family!\n\nLet me know if you can make it.\n\nSarah', 
    threats: [] 
  },
  { 
    id: 5, 
    sender: 'IT Department', 
    email: 'admin@1t-support-desk.com', 
    subject: 'Password Expiry Notice', 
    preview: 'Your corporate password expires in 2 hours. Reset immediately...', 
    date: '2 days ago', 
    unread: false, 
    risk: 'dangerous', 
    score: 88, 
    hasAttachment: true, 
    body: 'URGENT: Your corporate network password expires in 2 hours.\n\nFailure to reset will result in account lockout. Click below to reset:\nhttps://1t-support-desk.com/reset\n\nPlease have your employee ID and current password ready.\n\nIT Support', 
    threats: [
      'Spoofed IT department',
      'Fake urgency (2 hour deadline)',
      'Suspicious domain (1t-support-desk.com)',
      'Requests current password',
      'Malicious attachment detected'
    ] 
  },
  { 
    id: 6, 
    sender: 'GitHub', 
    email: 'noreply@github.com', 
    subject: '[GitHub] New login from Chrome on Windows', 
    preview: 'A new sign-in was detected on your GitHub account from...', 
    date: '3 days ago', 
    unread: false, 
    risk: 'safe', 
    score: 5, 
    hasAttachment: false, 
    body: 'Hi there,\n\nA new sign-in to your GitHub account was detected:\n\n- Browser: Chrome 120\n- OS: Windows 11\n- Location: San Francisco, CA\n- IP: 192.168.1.xxx\n\nIf this was you, no action is needed.\n\nThe GitHub Team', 
    threats: [] 
  }
];

const mockStats = { 
    total: 1247, 
    safe: 1089, 
    suspicious: 112, 
    malicious: 46 
};

const mockTopDomains = [
    { domain: 'amaz0n-verify.com', count: 23 },
    { domain: 'netflix-renew.net', count: 18 },
    { domain: '1t-support-desk.com', count: 15 },
    { domain: 'paypa1-secure.com', count: 12 },
    { domain: 'g00gle-verify.net', count: 9 }
];

const mockRecentActivity = [
    { action: 'Blocked phishing email', time: '2 hours ago', icon: 'shield' },
    { action: 'Connected Gmail account', time: '1 day ago', icon: 'link' },
    { action: 'Updated security settings', time: '3 days ago', icon: 'settings' },
    { action: 'Generated weekly report', time: '1 week ago', icon: 'bar-chart-2' }
];

export { mockEmails, mockStats, mockTopDomains, mockRecentActivity };
