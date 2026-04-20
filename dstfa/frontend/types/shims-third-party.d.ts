declare module "react-mermaid2" {
  import type { ComponentType } from "react";

  export type MermaidProps = {
    name?: string;
    chart?: string;
    config?: Record<string, unknown>;
  };

  const Mermaid: ComponentType<MermaidProps>;
  export default Mermaid;
}
