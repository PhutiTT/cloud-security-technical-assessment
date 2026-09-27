# Question 3 - Region restriction SCP

`region-restriction.json` is an AWS Organizations **deny guardrail** for regional API requests outside `eu-west-1` (Ireland). It does not grant access; identity policies still control allowed actions. This is a deployment example, not an attached policy.

## Reasoning and limits

The explicit deny uses `aws:RequestedRegion` and `NotAction` to exempt services with global endpoints, such as IAM, STS, CloudFront, Route 53, and Organizations. Without exceptions, normal sign-in, identity management, DNS, and support flows could fail because their APIs are handled outside `eu-west-1`. The exemption list is intentionally small and must be reviewed against the organization's global-service needs. **It is not literally possible to confine every global AWS service to eu-west-1 using this key.** The exceptions remain governed by IAM and other controls, but this SCP does not restrict their regional use. AWS examples discuss the [global-service caveat](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_examples_aws_deny-requested-region.html) and [regional guardrail pattern](https://docs.aws.amazon.com/prescriptive-guidance/latest/aws-startup-security-baseline/acct-17.html).

`aws:RequestedRegion` governs the API endpoint, not necessarily every downstream resource or cross-region effect (for example, a replication request made from an allowed endpoint). Add service-specific controls where data residency is required, and check for existing resources outside Ireland. An SCP applies to member accounts, including their root users, but not to the organization management account; it does not directly constrain external principals through a resource policy. See [AWS SCP effects](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html).

## Deployment process

1. Confirm the organization has all features and SCPs enabled, identify a pilot OU/member account and owner, inventory non-Ireland activity from CloudTrail/service-last-accessed data, and review global service exceptions. Do not attach to the root first.
2. Validate JSON and review the effective policy tree. Keep `FullAWSAccess` or another required allow SCP attached, because this deny statement grants nothing. Create a policy from the **management account**:

   ```bash
   python3 -m json.tool required-scp/region-restriction.json > /dev/null
   aws organizations create-policy \
     --name DenyRegionalActionsOutsideEuWest1 \
     --description 'Deny regional AWS API calls outside Ireland' \
     --type SERVICE_CONTROL_POLICY \
     --content file://required-scp/region-restriction.json
   ```

3. Record the returned policy ID, then attach to a **pilot** OU/account (`ou-...` or 12-digit account ID):

   ```bash
   aws organizations attach-policy --policy-id p-EXAMPLE --target-id ou-EXAMPLE
   ```

4. With a principal in that member account, try representative **non-exempt** actions in `eu-west-1` and `eu-west-2`: an IAM-authorized read such as `ec2:DescribeInstances` should work in Ireland and get an explicit deny outside it. Also test required IAM, STS, DNS, CloudFront, billing, support, and DR workflows, as well as the console. Review CloudTrail failures and affected automation.
5. Roll out OU by OU with change control. If critical operations break, detach from the affected pilot target, inspect denied calls, revise exceptions narrowly, and retest. Avoid a blanket exemption for a regional service.

AWS recommends piloting SCPs in a separate OU before broad attachment: [testing effects of SCPs](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html#orgs_manage_policies_scps-testing).
