import type { AnalysisStatus } from "@/lib/types";
import { statusColor } from "@/lib/utils";

interface Props {
  status: AnalysisStatus;
}

export default function Badge({ status }: Props) {
  return (
    <span className={`inline-block text-xs font-medium px-2 py-0.5 rounded-full ${statusColor(status)}`}>
      {status}
    </span>
  );
}
