import http from "k6/http";
import { check } from "k6";

export const options = {
  scenarios: {
    event_ingest: {
      executor: "constant-arrival-rate",
      rate: 50,
      timeUnit: "1s",
      duration: "2m",
      preAllocatedVUs: 20,
      maxVUs: 100,
    },
  },
  thresholds: {
    http_req_failed: ["rate<0.01"],
    http_req_duration: ["p(95)<500"],
  },
};

const base = __ENV.BASE_URL || "http://127.0.0.1:8000";
const key = __ENV.API_KEY || "dev-admin-key";

export default function () {
  const id = `${__VU}-${__ITER}`;
  const response = http.post(
    `${base}/events`,
    JSON.stringify({
      source: "load-test",
      name: "Agent platform load validation",
      category: "contract_test",
      severity: "medium",
      entities: [{ type: "host", id: `host:${id}` }],
    }),
    { headers: { "content-type": "application/json", "x-api-key": key, "idempotency-key": `k6-${id}` } },
  );
  check(response, { "workflow accepted": (result) => result.status === 200 });
}
