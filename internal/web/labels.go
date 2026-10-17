package web

import "github.com/oyaguma3/radsec-edge/internal/db"

func triggerLabel(s string) string {
	switch s {
	case db.TriggerApply:
		return "反映"
	case db.TriggerReconcile:
		return "整合"
	case db.TriggerCRL:
		return "CRL の更新"
	}
	return s
}

func actionLabel(s string) string {
	switch s {
	case "none":
		return "なし"
	case "created":
		return "作成して起動"
	case "recreated":
		return "作り直して起動"
	case "started":
		return "起動"
	case "restart":
		return "再起動"
	case "sighup":
		return "SIGHUP"
	case "stop":
		return "停止"
	case "", "ensure":
		return "-"
	}
	return s
}

func resultLabel(s string) string {
	switch s {
	case db.ResultOK:
		return "成功"
	case db.ResultFailed:
		return "失敗（前の版のまま）"
	case db.ResultRolledBack:
		return "失敗（前の版に戻した）"
	}
	return s
}

func stateLabel(s string) string {
	switch s {
	case "running":
		return "稼働中"
	case "restarting":
		return "再起動中"
	case "exited":
		return "停止"
	case "created":
		return "作成済み（未起動）"
	case "paused":
		return "一時停止"
	case "dead":
		return "異常終了"
	case "":
		return "なし"
	}
	return s
}

var auditLabels = map[string]string{
	"tenant.create":           "テナントの作成",
	"tenant.update":           "テナントの変更",
	"tenant.delete":           "テナントの削除",
	"tenant.apply":            "反映",
	"tenant.start":            "起動",
	"tenant.stop":             "停止",
	"tenant.restart":          "再起動",
	"client_ca.import":        "クライアントCA の取り込み",
	"server.csr":              "サーバー証明書の CSR",
	"probe.csr":               "ヘルスチェック用の証明書の CSR",
	"server_cert.import":      "サーバー証明書の取り込み",
	"probe_cert.import":       "ヘルスチェック用の証明書の取り込み",
	"crl.install":             "CRL の更新",
	"ap.put":                  "AP の登録",
	"ap.delete":               "AP の削除",
	"container.remove_orphan": "テナントのないコンテナの削除",
}

func auditLabel(s string) string {
	if l, ok := auditLabels[s]; ok {
		return l
	}
	return s
}
