"use client";
import styles from "./page.module.css";
import {
  bytesToHex,
  NoTagFoundError,
  TwN4SimpleProtocol,
} from "@/web-serial-simple-protocol";

import {
  encryptKeyStore,
  saveToLocalStorage,
  hexToKeyBytes,
  DesfireTokenSpec,
  DesfireKey,
} from "@/key-crypto";
import { buildFileContent, FileTemplate } from "@/desfire-template";
import { useEffect, useRef, useState } from "react";

interface Address {
  street: string;
  city: string;
  postalCode: string;
  country: string;
}

interface PersonalData {
  firstName: string;
  lastName: string;
  address?: Address;
}

interface User {
  bayzeitId: string;
  ricohId: string;
  personalData: PersonalData;
}

export default function Home() {
  const addMessage = (msgs: string[], msg: string): string[] => [...msgs, msg];

  const userFileTemplate: FileTemplate = {
    name: "user-data",
    fields: [
      {
        path: "personalData.firstName",
        length: 16,
        encoding: "utf8",
        pad: " ",
      },
      { path: "personalData.lastName", length: 16, encoding: "utf8", pad: " " },
      {
        path: "personalData.address.street",
        length: 32,
        encoding: "utf8",
        pad: " ",
      },
      { path: "bayzeitId", length: 16, encoding: "utf8", pad: " " },
      { path: "ricohId", length: 16, encoding: "utf8", pad: " " },
    ],
  };

  const baseKeySettings: DesfireKey = {
    kid: 0,
    keyHex: "00000000000000000000000000000000",
    keyType: "3DES",
    keyVersion: 0,
    configurationChangeable: true,
    freeCreateDelete: false,
    freeDirectoryList: true,
    allowChangeMasterKey: true,
    changeKeyAccessRights: 0x0000,
  };

  const keyspec: DesfireTokenSpec = {
    piccMasterKey: {
      kid: 0,
      keyHex: "3abc6245243ac97858c2e1924f47de4f",
      keyType: "3DES",
      keyVersion: 0,
      configurationChangeable: true,
      freeCreateDelete: false,
      freeDirectoryList: true,
      allowChangeMasterKey: true,
      changeKeyAccessRights: 0x0000,
    },
    applications: [
      {
        aid: "00F111D1",
        personalized: true,
        keyCount: 4,
        files: [],
        keys: [
          {
            ...baseKeySettings,
            keyHex: "22eb6c1f498d58392b71c2bfcd10a155",
            kid: 0,
          },
          {
            ...baseKeySettings,
            keyHex: "a49f6a32670a81e4c872454786aa8cc2",
            kid: 1,
          },
          {
            ...baseKeySettings,
            keyHex: "599a4ea4dc3237535aa8889b67912f12",
            kid: 2,
          },
          {
            ...baseKeySettings,
            keyHex: "d8ae8b3ceeac931637ea76baa1add9b9",
            kid: 3,
          },
        ],
      },
    ],
  };

  const tryPicc = async (
    protocol: TwN4SimpleProtocol,
    key: string,
  ): Promise<boolean> => {
    try {
      const app = await protocol.desfireSelectApplication(0x00, 0x000000);
      if (!app) {
        return false;
      }
      const auth = await protocol.desfireAuthenticate({
        cryptoEnv: 0x00,
        keyNo: 0x00,
        key: hexToKeyBytes(key),
        keyType: 0x00,
        mode: 0x01,
      });
      if (!auth) {
        return false;
      }
      return true;
    } catch {
      return false;
    }
  };

  const a: User = {
    bayzeitId: "Test",
    ricohId: "Test 1",
    personalData: {
      firstName: "Max",
      lastName: "Musterfrau",
      address: {
        street: "Musterstrasse 1",
        city: "Musterstadt",
        postalCode: "12345",
        country: "Germany",
      },
    },
  };

  const isHmToken = async (
    protocol: TwN4SimpleProtocol,
    key: string,
  ): Promise<boolean> => {
    return await tryPicc(protocol, key);
  };

  const isVanillaToken = async (
    protocol: TwN4SimpleProtocol,
  ): Promise<boolean> => {
    const defaultHmKey = "00000000000000000000000000000000";
    return await isHmToken(protocol, defaultHmKey);
  };

  const [messages, setMessages] = useState<string[]>([]);
  const [protocol, setProtocol] = useState<TwN4SimpleProtocol | undefined>(
    undefined,
  );

  const logRef = useRef<HTMLDivElement>(null);
  // keep the newest log line in view as the operation progresses
  useEffect(() => {
    const log = logRef.current;
    if (log) {
      log.scrollTop = log.scrollHeight;
    }
  }, [messages]);

  const connect = async () => {
    try {
      const protocol = new TwN4SimpleProtocol();
      await protocol.connect();
      setMessages((msgs) => addMessage(msgs, "Connected to device"));
      await protocol.setMifareOnly();
      setMessages((msgs) => addMessage(msgs, "Set to MIFARE only mode"));
      console.log("Protocol connected:", protocol);
      setProtocol(protocol);
    } catch (error) {
      setMessages((msgs) =>
        addMessage(
          msgs,
          "Failed to connect to device: " + (error as Error).message,
        ),
      );
      console.error("Failed to connect to device:", error);
      return;
    }
  };
  const readKey = async (
    generateHmApp: boolean = false,
    writeDefault: boolean = false,
  ) => {
    if (!protocol) {
      setMessages((msgs) => addMessage(msgs, "Not connected to device"));
      return;
    }
    try {
      let tag;
      while (true) {
        try {
          tag = await protocol.searchTag(0x16);
          break;
        } catch (error) {
          if (!(error instanceof NoTagFoundError)) {
            throw error;
          }
          setMessages((msgs) => addMessage(msgs, "No tag found, retrying..."));
          // Wait a bit before retrying
          await new Promise((resolve) => setTimeout(resolve, 1000));
        }
      }

      const uid = bytesToHex(tag.uid);
      setMessages((msgs) => addMessage(msgs, `Found Tag. UID: ${uid}`));

      if (!writeDefault) {
        setMessages((msgs) => addMessage(msgs, "Only reading ..."));

        if (await isHmToken(protocol, keyspec.piccMasterKey.keyHex)) {
          setMessages((msgs) => addMessage(msgs, "Tag is already a HM token"));
        } else if (await isVanillaToken(protocol)) {
          setMessages((msgs) => addMessage(msgs, "Tag is a vanilla token"));
        } else {
          setMessages((msgs) =>
            addMessage(
              msgs,
              "Tag is neither vanilla nor HM; Unknown PICC used",
            ),
          );
        }
        return;
      }

      const crypto = await protocol.cryptoInit(
        0x00,
        0x03,
        hexToKeyBytes("00000000000000000000000000000000"),
      );
      if (!crypto) {
        setMessages((msgs) => addMessage(msgs, "Failed to initialize crypto"));
        return;
      }
      setMessages((msgs) => addMessage(msgs, "Crypto initialized"));

      const app = await protocol.desfireSelectApplication(0x00, 0x000000);
      if (!app) {
        setMessages((msgs) => addMessage(msgs, "Failed to select application"));
        return;
      }
      setMessages((msgs) => addMessage(msgs, "Selected application 0x000000"));

      if (await isVanillaToken(protocol)) {
        setMessages((msgs) =>
          addMessage(
            msgs,
            "Tag is a vanilla token, setting PICC master key to default HM key",
          ),
        );

        const format = await protocol.desfireFormatTag(0x00);
        if (!format) {
          setMessages((msgs) => addMessage(msgs, "Failed to format tag"));
          return;
        }
        setMessages((msgs) => addMessage(msgs, "Formatted tag successfully"));

        const resp = await protocol.desfireChangeKey({
          cryptoEnv: 0x00,
          keyNo: 0x00,
          oldKey: hexToKeyBytes("00000000000000000000000000000000"),
          newKey: hexToKeyBytes(keyspec.piccMasterKey.keyHex),
          keyType: keyspec.piccMasterKey.keyType,
          configurationChangeable:
            keyspec.piccMasterKey.configurationChangeable,
          freeCreateDelete: keyspec.piccMasterKey.freeCreateDelete,
          freeDirectoryList: keyspec.piccMasterKey.freeDirectoryList,
          allowChangeMasterKey: keyspec.piccMasterKey.allowChangeMasterKey,
          numberOfKeys: 1,
          keyVersion: keyspec.piccMasterKey.keyVersion,
          changeKeyAccessRights: keyspec.piccMasterKey.changeKeyAccessRights,
        });
        console.log(resp);
        if (!resp) {
          setMessages((msgs) => addMessage(msgs, "Failed to change key"));
          return;
        }

        await protocol.desfireAuthenticate({
          cryptoEnv: 0x00,
          keyNo: 0x00,
          key: hexToKeyBytes(keyspec.piccMasterKey.keyHex),
          keyType: keyspec.piccMasterKey.keyType,
          mode: 0x01,
        });

        await protocol.desfireChangeKeySettings({
          cryptoEnv: 0x00,
          keyType: 0x00,
          configurationChangeable:
            keyspec.piccMasterKey.configurationChangeable,
          freeCreateDelete: keyspec.piccMasterKey.freeCreateDelete,
          freeDirectoryList: keyspec.piccMasterKey.freeDirectoryList,
          allowChangeMasterKey: keyspec.piccMasterKey.allowChangeMasterKey,
          numberOfKeys: 1,
          changeKeyAccessRights: keyspec.piccMasterKey.changeKeyAccessRights,
        });

        setMessages((msgs) =>
          addMessage(msgs, `Changed key 0x00 successfully.`),
        );
      }
      if (await isHmToken(protocol, keyspec.piccMasterKey.keyHex)) {
        setMessages((msgs) => addMessage(msgs, "Tag is already a HM token"));
        return;
      }

      const apps = await protocol.desfireGetApplicationIds(0x00, 0x1c);

      for (const app of keyspec.applications) {
        if (!apps.includes(app.aid) && app.personalized && generateHmApp) {
          setMessages((msgs) =>
            addMessage(msgs, "HM Application not found on tag"),
          );
          await protocol.createApplication({
            cryptoEnv: 0x00,
            aidBigEndian: app.aid,
            keyType: 0x00,
            numberOfKeys: 4,
            freeCreateDelete: false,
            freeDirectoryList: true,
            changeKeyAccessRights: 0x0000,
            allowChangeMasterKey: true,
            configurationChangeable: true,
          });
          setMessages((msgs) =>
            addMessage(msgs, "Created HM Application on tag"),
          );
          await protocol.desfireSelectApplication(0x00, app.aid);
          await protocol.desfireAuthenticate({
            cryptoEnv: 0x00,
            keyNo: 0x00,
            key: hexToKeyBytes("00000000000000000000000000000000"),
            keyType: 0x00,
            mode: 0x01,
          });
          setMessages((msgs) =>
            addMessage(msgs, "Selected HM Application on tag"),
          );

          for (const keyConfig of app.keys) {
            await protocol.desfireChangeKey({
              cryptoEnv: 0x00,
              keyNo: keyConfig.kid,
              keyType: 0x00,
              keyVersion: 0x00,
              oldKey: hexToKeyBytes("00000000000000000000000000000000"),
              newKey: hexToKeyBytes(keyConfig.keyHex),
              configurationChangeable: true,
              freeCreateDelete: false,
              freeDirectoryList: true,
              allowChangeMasterKey: true,
              numberOfKeys: 4,
              changeKeyAccessRights: 0x0000,
            });
            setMessages((msgs) =>
              addMessage(msgs, `Added key ${keyConfig.kid}`),
            );
            await protocol.desfireAuthenticate({
              cryptoEnv: 0x00,
              keyNo: 0x00,
              key: hexToKeyBytes(app.keys[0].keyHex),
              keyType: 0x00,
              mode: 0x01,
            });
          }
          await protocol.desfireCreateStandardFile({
            cryptoEnv: 0x00,
            fileNo: 0x00,
            commSet: 0x00,
            accessRights: 0x2110,
            fileSize: 16,
          });
          setMessages((msgs) =>
            addMessage(msgs, "Created Standard File on HM Application"),
          );
          await protocol.desfireCreateStandardFile({
            cryptoEnv: 0x00,
            fileNo: 0x01,
            commSet: 0x00,
            accessRights: 0x3110,
            fileSize: 64,
          });
          setMessages((msgs) =>
            addMessage(msgs, "Created Standard File on HM Application"),
          );
        } else if (apps.includes(app.aid)) {
          setMessages((msgs) =>
            addMessage(msgs, "HM Application found on tag"),
          );
        }
      }
    } catch (error) {
      setMessages((msgs) =>
        addMessage(msgs, "Error occurred: " + (error as Error).message),
      );
      console.error("Failed to connect to device:", error);
    }
  };
  const format = async () => {
    if (!protocol) {
      setMessages((msgs) => addMessage(msgs, "Not connected to device"));
      return;
    }
    if (await isVanillaToken(protocol)) {
    } else if (await isHmToken(protocol, keyspec.piccMasterKey.keyHex)) {
    }
    try {
      const format = await protocol.desfireFormatTag(0x00);
      if (!format) {
        setMessages((msgs) => addMessage(msgs, "Failed to format tag"));
        return;
      }
      setMessages((msgs) => addMessage(msgs, "Formatted tag successfully"));
    } catch (error) {
      setMessages((msgs) =>
        addMessage(msgs, "Error occurred: " + (error as Error).message),
      );
    }
    if (await isHmToken(protocol, keyspec.piccMasterKey.keyHex)) {
      const resp = await protocol.desfireChangeKey({
        cryptoEnv: 0x00,
        keyNo: 0x00,
        newKey: hexToKeyBytes("00000000000000000000000000000000"),
        oldKey: hexToKeyBytes(keyspec.piccMasterKey.keyHex),
        keyType: keyspec.piccMasterKey.keyType,
        configurationChangeable: keyspec.piccMasterKey.configurationChangeable,
        freeCreateDelete: keyspec.piccMasterKey.freeCreateDelete,
        freeDirectoryList: keyspec.piccMasterKey.freeDirectoryList,
        allowChangeMasterKey: keyspec.piccMasterKey.allowChangeMasterKey,
        numberOfKeys: 1,
        keyVersion: keyspec.piccMasterKey.keyVersion,
        changeKeyAccessRights: keyspec.piccMasterKey.changeKeyAccessRights,
      });
    }
  };

  return (
    <div className={styles.page}>
      <main className={styles.shell}>
        <header className={styles.header}>
          <div>
            <h1 className={styles.title}>Key Encoder</h1>
            <p className={styles.subtitle}>
              DESFire provisioning over the TWN4 Simple Protocol
            </p>
          </div>
          <span
            className={`${styles.status} ${protocol ? styles.statusOnline : ""}`}
          >
            <span className={styles.statusDot} />
            {protocol ? "Reader connected" : "No reader"}
          </span>
        </header>

        <div className={styles.toolbar}>
          <button
            className={`${styles.button} ${styles.primary}`}
            onClick={() => connect()}
          >
            {protocol ? "Reconnect" : "Connect reader"}
          </button>
          <button
            className={styles.button}
            onClick={() => readKey(false, false)}
            disabled={!protocol}
          >
            Read only
          </button>
          <button
            className={styles.button}
            onClick={() => readKey(false, true)}
            disabled={!protocol}
          >
            Read &amp; write default
          </button>
          <button
            className={styles.button}
            onClick={() => readKey(true, true)}
            disabled={!protocol}
          >
            Read &amp; add HM app
          </button>
          <button
            className={`${styles.button} ${styles.danger}`}
            onClick={() => format()}
            disabled={!protocol}
          >
            Format tag
          </button>
        </div>

        <section className={styles.console}>
          <div className={styles.consoleHeader}>
            <span className={styles.consoleTitle}>Activity log</span>
            <button
              className={styles.clear}
              onClick={() => setMessages([])}
              disabled={messages.length === 0}
            >
              Clear
            </button>
          </div>
          <div className={styles.log} ref={logRef} aria-live="polite">
            {messages.length === 0 ? (
              <p className={styles.empty}>
                Waiting for a reader. Connect one to begin.
              </p>
            ) : (
              messages.map((msg, index) => (
                <div className={styles.line} key={index}>
                  <span className={styles.lineNo}>
                    {String(index + 1).padStart(3, "0")}
                  </span>
                  <span className={styles.lineText}>{msg}</span>
                </div>
              ))
            )}
          </div>
        </section>
      </main>
    </div>
  );
}
