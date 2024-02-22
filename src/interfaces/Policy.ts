import { Group } from "@/interfaces/Group";

export interface Policy {
  id?: string;
  name: string;
  description: string;
  enabled: boolean;
  query: string;
  rules: PolicyRule[];
  source_posture_checks: string[];
}

export interface PolicyRule {
  id?: string;
  name: string;
  description: string;
  enabled: boolean;
  sources: Group[] | string[] | null;
  destinations: Group[] | string[] | null;
  bidirectional: boolean;
  action: string;
  protocol: Protocol;
  ports: string[];
}

export type Protocol = "all" | "tcp" | "udp" | "icmp";
