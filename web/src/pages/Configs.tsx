import { useEffect, useMemo, useState } from "react";
import QRCode from "qrcode";
import type { IssuedDevice } from "../api/client";
import { configFile } from "../lib/config";
import { fa } from "../fa";

function download(name: string, data: BlobPart, type: string) {
  const url = URL.createObjectURL(new Blob([data], { type }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/** The config of a freshly issued Device, shown once: a QR code and the
 * file. The private key exists only in this page's memory. */
export function Configs({ issued, privateKey, onSaved }: { issued: IssuedDevice; privateKey: string; onSaved: () => void }) {
  const file = useMemo(() => configFile(issued.config, privateKey), [issued, privateKey]);
  const [qr, setQr] = useState("");
  useEffect(() => {
    QRCode.toDataURL(file.text, { errorCorrectionLevel: "M", margin: 1, width: 280 }).then(setQr);
  }, [file]);

  return (
    <section className="configs">
      <h1>
        {fa.configsTitle}: {issued.device.name}
      </h1>
      <p className="warning">{fa.configsOnce}</p>
      <figure>
        {qr && <img src={qr} alt={file.name} />}
        <button type="button" data-testid="download-conf" onClick={() => download(file.name, file.text, "text/plain")}>
          {fa.download} <span dir="ltr">{file.name}</span>
        </button>
      </figure>
      <p className="hint">{fa.iphoneHint}</p>
      <p className="hint">{fa.stuckHint}</p>
      <button type="button" onClick={onSaved}>
        {fa.saved}
      </button>
    </section>
  );
}
