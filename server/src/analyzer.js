const patterns = [
  { re: /\b(urgent|immediately|act now|within \d+ hours|final warning)\b/i, points: 15, label: "Urgency or pressure", why: "Scammers create time pressure so people act before checking details." },
  { re: /\b(otp|one[- ]time password|password|pin|cvv|card number)\b/i, points: 30, label: "Requests sensitive credentials", why: "Legitimate support teams should not ask you to share an OTP, PIN, CVV or password in a message." },
  { re: /\b(you have won|winner|lottery|prize|claim your reward)\b/i, points: 18, label: "Unexpected prize or reward", why: "Unexpected prizes are commonly used as bait, especially when a fee or link is involved." },
  { re: /\b(pay|send|transfer|deposit).{0,35}\b(fee|charge|tax|processing|verification)\b|\b(registration fee|security deposit|refundable fee)\b/i, points: 25, label: "Payment requested upfront", why: "Advance payments to unlock a prize, refund, job or account are a strong warning sign." },
  { re: /\b(account (?:blocked|suspended|locked)|kyc update|verify your account)\b/i, points: 18, label: "Account-threat language", why: "Fake bank or platform alerts often threaten account suspension to prompt a click." },
  { re: /\b(guaranteed returns|double your money|risk[- ]free profit|100% profit)\b/i, points: 25, label: "Unrealistic financial promise", why: "Guaranteed high returns are a common investment-fraud tactic." },
  { re: /\b(no experience required|earn \₹?[\d,]+ (?:daily|per day)|work from home.*easy money)\b/i, points: 12, label: "Unusually attractive offer", why: "Vague, unusually high earnings with little work can be used to attract victims." },
  { re: /\b(click here|login now|verify now|download this app)\b/i, points: 10, label: "Call to click or install", why: "Unsolicited links and app installs can lead to credential theft or malware." }
];

export function analyzeMessage(message = "") {
  const text = String(message).trim();
  if (text.length < 4) {
    const error = new Error("Please enter a message with at least 4 characters.");
    error.status = 400;
    throw error;
  }
  let score = 0;
  const findings = [];
  for (const p of patterns) {
    if (p.re.test(text)) {
      score += p.points;
      findings.push({ title: p.label, explanation: p.why, severity: p.points >= 25 ? "high" : "medium" });
    }
  }
  const urls = text.match(/https?:\/\/[^\s<>"']+|www\.[^\s<>"']+/gi) || [];
  if (urls.length) {
    score += 12;
    findings.push({ title: "Contains an external link", explanation: "Do not open unexpected links. Check the exact domain independently; HTTPS alone does not prove a site is genuine.", severity: "medium" });
  }
  if (/(bit\.ly|tinyurl|t\.co|cutt\.ly|rb\.gy)\//i.test(text)) {
    score += 12;
    findings.push({ title: "Shortened link detected", explanation: "A shortened URL hides its final destination. Verify it before visiting.", severity: "medium" });
  }
  score = Math.min(score, 100);
  return {
    score,
    level: score >= 55 ? "High Risk" : score >= 25 ? "Suspicious" : "Low Risk",
    summary: score >= 55 ? "Several strong warning signs were found. Do not interact until independently verified." : score >= 25 ? "Some warning signs were found. Verify the sender and claims using official channels." : "Few common warning signs were detected. This does not establish that the message is genuine.",
    findings,
    checkedAt: new Date().toISOString(),
    disclaimer: "Automated screening can miss new scams and can flag legitimate messages. Never share OTPs, passwords, PINs or CVVs."
  };
}

export function analyzeJob(input = {}) {
  const fields = Object.fromEntries(Object.entries(input).map(([k,v]) => [k, String(v ?? "").trim()]));
  const combined = Object.values(fields).join(" ");
  let score = 0;
  const findings = [];
  const add = (points, title, explanation, severity = "medium") => {
    score += points; findings.push({ title, explanation, severity });
  };

  if (/application fee|registration fee|training fee|security deposit|processing fee|pay.*job|fee.*job/i.test(combined) || (fields.applicationFee && !/^(no|none|0|free|not applicable)$/i.test(fields.applicationFee))) {
    add(35, "Upfront payment requested", "A genuine employer generally does not require candidates to pay to secure a job. Verify directly with the company's official HR team.", "high");
  }
  if (/\b(guaranteed selection|direct joining|no interview|instant job|100% placement)\b/i.test(combined)) {
    add(18, "Guaranteed selection or no interview", "Promises of guaranteed hiring without a credible selection process deserve careful verification.");
  }
  if (/\b(earn|salary|₹)\s*[\d,]{5,}.*\b(per day|daily|for 1 hour|part time)\b/i.test(combined)) {
    add(20, "Unusually high pay claim", "Very high pay for minimal work can be a lure. Compare the role and salary with independently published vacancies.");
  }
  if (fields.recruiterEmail && !/@(gmail|yahoo|outlook|hotmail)\./i.test(fields.recruiterEmail) && !/@[a-z0-9.-]+\.[a-z]{2,}$/i.test(fields.recruiterEmail)) {
    add(15, "Recruiter email looks unusual", "The email address does not look like a standard business email. Confirm the exact domain on the company's official website.");
  } else if (/@(gmail|yahoo|outlook|hotmail)\./i.test(fields.recruiterEmail)) {
    add(18, "Personal email used for recruitment", "A free email address is not proof of fraud, but an unsolicited recruiter using one should be verified through the company's official careers page.");
  }
  if (/\b(whatsapp only|telegram only|contact on telegram)\b/i.test(combined)) {
    add(15, "Recruitment restricted to messaging apps", "A process conducted only through WhatsApp or Telegram is harder to verify. Contact the employer using independently found details.");
  }
  if (!fields.company) add(8, "Company name missing", "Without a company name, it is difficult to verify who is offering the role.");
  if (!fields.role) add(5, "Job role missing", "A credible vacancy should describe the role and responsibilities clearly.");
  if (!fields.jobDescription || fields.jobDescription.length < 30) add(8, "Job description is too vague", "Ask for a detailed job description, location, reporting structure and selection process.");
  if (fields.company && /\b(ltd|limited|private limited|pvt)\b/i.test(fields.company) === false) {
    add(4, "Company legal identity not clear", "Check the registered legal name and official website. This alone is not evidence of fraud.", "low");
  }
  score = Math.min(score, 100);
  const level = score >= 55 ? "High Risk" : score >= 25 ? "Suspicious" : "Low Risk";
  return {
    score, level,
    summary: score >= 55 ? "This offer has multiple warning signs. Do not pay or share documents until verified." : score >= 25 ? "Some details need independent verification before proceeding." : "Few common warning signs were detected, but the employer and vacancy are not verified.",
    findings,
    verificationSteps: [
      "Find the company's official website independently; do not rely only on links in the offer.",
      "Check whether the same vacancy appears on the official careers page.",
      "Call or email HR using contact details published on the official website.",
      "Never pay recruitment, interview, training or security-deposit fees without independently verifying the claim.",
      "Do not share OTPs, bank PINs, passwords or identity documents with an unverified recruiter."
    ],
    checkedAt: new Date().toISOString(),
    disclaimer: "This is a warning-sign assessment, not a background check or confirmation that a company/job is genuine."
  };
}
