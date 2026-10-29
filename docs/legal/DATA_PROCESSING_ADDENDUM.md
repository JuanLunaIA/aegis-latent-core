<!--
Copyright (c) 2026 Juan Luna. All rights reserved.
SPDX-License-Identifier: LicenseRef-Aegis-Commercial-1.0
Licensed under the Aegis Commercial License 1.0; see LICENSE and NOTICE.
-->

# Data Processing Addendum (DPA)

**Version:** 1.0-draft · **Status:** `[COUNSEL-REVIEW-REQUIRED]`
This DPA forms part of the Terms of Service when the customer processes personal
data through the hosted Service and the parties sign it. It does not apply to a
self-hosted gateway, where the customer is the controller and the processor.

## 1. Roles and scope

1.1 Customer is the controller; Juan Luna ("Processor") processes personal data
only to provide the Service, on documented instructions, and not for its own
purposes.

1.2 The subject matter, duration, nature and purpose of processing, and the
categories of data subjects, are described in Annex A.

## 2. Processor obligations

2.1 Process only on documented instructions, including transfers, unless required
by law (and then inform the Customer unless prohibited).

2.2 Ensure personnel are bound by confidentiality.

2.3 Implement the technical and organisational measures in Annex B.

2.4 Assist with data-subject requests, impact assessments and prior consultations
to the extent the Customer cannot do so itself.

2.5 Notify the Customer without undue delay, and in any event within 72 hours, of
a personal-data breach, with the information required by Art. 33 GDPR.

2.6 Delete or return data at the end of the service, subject to legal retention.

2.7 Make available the information needed to demonstrate compliance and allow
audits on reasonable notice, no more than once a year unless a breach requires it.

## 3. Subprocessors

3.1 The list is `SUBPROCESSORS.md`. The Customer authorises them generally and
the Processor gives notice before adding one that processes personal data,
allowing 30 days to object.

3.2 The Processor imposes the same obligations on each subprocessor.

## 4. International transfers

4.1 The Service runs in `us-east-1`. Where required, the parties rely on the
Standard Contractual Clauses or an adequacy decision, as identified in the Order.

4.2 The Processor will notify the Customer of any change to the hosting region.

## 5. Liability and precedence

5.1 The liability cap in the Terms applies to this DPA.

5.2 If this DPA conflicts with the Terms on data protection, this DPA prevails.

## Annex A — Processing details

- Data subjects: the Customer's users and administrators.
- Data: email, organisation, role, session metadata (IP, user agent), API key
  prefixes and hashes, usage metadata, support messages.
- Purpose: authentication, tenancy, metering, billing, security.
- Duration: the subscription term plus the retention periods in the privacy
  policy.

## Annex B — Technical and organisational measures

- Encryption in transit (TLS) and at rest (RDS storage encryption).
- Passwords hashed with scrypt; API keys stored as hashes; opaque sessions.
- Network isolation: private subnets, security groups, no public database.
- Least-privilege IAM, secrets in AWS SSM SecureString, audit logs.
- Backups with a documented restore drill.
- Access to production limited to the operator, logged.
