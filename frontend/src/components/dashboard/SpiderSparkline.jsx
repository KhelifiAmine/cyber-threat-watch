import { AreaChart, Area, ResponsiveContainer } from "recharts";

export default function SpiderSparkline({ runs }) {
  if (!runs || runs.length === 0) return <span className="text-gray-600 text-[10px]">no data</span>;

  return (
    <div className="w-[80px] h-[24px] inline-block">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={runs} margin={{ top: 2, right: 0, left: 0, bottom: 2 }}>
          <Area
            type="monotone"
            dataKey="items"
            stroke="#38BDF8"
            fill="#38BDF8"
            fillOpacity={0.15}
            strokeWidth={1.5}
            dot={false}
            isAnimationActive={false}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
