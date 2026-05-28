import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as eks from 'aws-cdk-lib/aws-eks';
import * as iam from 'aws-cdk-lib/aws-iam';
import { KubectlV29Layer } from '@aws-cdk/lambda-layer-kubectl-v29';

export class EksStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // 1. VPC
    const vpc = new ec2.Vpc(this, 'EksVpc', {
      maxAzs: 2,
    });

    // 2. IAM Role for EKS Admin Access (🔥 FIX)
    const adminRole = new iam.Role(this, 'EksAdminRole', {
      assumedBy: new iam.AccountRootPrincipal(),
    });

    // 3. EKS Cluster
    const cluster = new eks.Cluster(this, 'EksCluster', {
      vpc,
      version: eks.KubernetesVersion.V1_29,
      kubectlLayer: new KubectlV29Layer(this, 'KubectlLayer'),
      defaultCapacity: 0,

      // 🔥 THIS IS THE KEY FIX
      mastersRole: adminRole,
    });

    // 4. Node Group
    cluster.addNodegroupCapacity('AppNodes', {
      instanceTypes: [new ec2.InstanceType('t3.medium')],
      desiredSize: 2,
    });
  }
}