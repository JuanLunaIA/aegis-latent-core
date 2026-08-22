import { MMRExplorer } from "@/components/MMRExplorer";

export default function MMRPage(){return <><h1>MMR inclusion proof</h1><p className="lede">Retrieve a persisted portable proof and verify it locally with Web Crypto against the root returned by the authenticated evidence API.</p><aside className="notice"><strong>Trust boundary:</strong> for third-party assurance, compare the root with an independently approved checkpoint. A root fetched from the same service is not an independent trust anchor.</aside><MMRExplorer/></>;}
