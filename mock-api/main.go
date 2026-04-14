package main

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// ─── Test data ────────────────────────────────────────────────────────────────

// reviewerEmails are the three test emails that return accessStatus: yes on /reviewer-check
var reviewerEmails = []string{
	"alice@example.com",
	"bob@example.com",
	"charlie@example.com",
}

type sysid struct {
	Value         string `json:"value"`
	Label         string `json:"label"`
	SysidName     string `json:"sysidName"`
	SysidTier     string `json:"sysidTier"`
	ReviewerGroup string `json:"reviewerGroup"`
}

var sysids = []sysid{
	{Value: "SYSID-10001", Label: "SYSID-10001 — Payments Gateway", SysidName: "Payments Gateway", SysidTier: "1", ReviewerGroup: "dso-sysid-10001-reviewer"},
	{Value: "SYSID-10002", Label: "SYSID-10002 — Customer Portal", SysidName: "Customer Portal", SysidTier: "2", ReviewerGroup: "dso-sysid-10002-reviewer"},
	{Value: "SYSID-10003", Label: "SYSID-10003 — Fraud Detection", SysidName: "Fraud Detection", SysidTier: "1", ReviewerGroup: "dso-sysid-10003-reviewer"},
	{Value: "SYSID-10004", Label: "SYSID-10004 — Reporting Engine", SysidName: "Reporting Engine", SysidTier: "3", ReviewerGroup: "dso-sysid-10004-reviewer"},
}

var accountsBySysid = map[string][]map[string]string{
	"SYSID-10001": {
		{"value": "aws-prod-payments-001", "label": "aws-prod-payments-001 (Production)"},
		{"value": "aws-nonprod-payments-002", "label": "aws-nonprod-payments-002 (Non-Production)"},
	},
	"SYSID-10002": {
		{"value": "aws-prod-portal-001", "label": "aws-prod-portal-001 (Production)"},
		{"value": "aws-nonprod-portal-002", "label": "aws-nonprod-portal-002 (Non-Production)"},
	},
	"SYSID-10003": {
		{"value": "aws-prod-fraud-001", "label": "aws-prod-fraud-001 (Production)"},
	},
	"SYSID-10004": {
		{"value": "aws-prod-reporting-001", "label": "aws-prod-reporting-001 (Production)"},
		{"value": "aws-nonprod-reporting-002", "label": "aws-nonprod-reporting-002 (Non-Production)"},
	},
}

var regionsByAccount = map[string][]map[string]string{
	"aws-prod-payments-001":     {{"value": "eu-west-1", "label": "eu-west-1 (Ireland)"}, {"value": "eu-central-1", "label": "eu-central-1 (Frankfurt)"}},
	"aws-nonprod-payments-002":  {{"value": "eu-west-1", "label": "eu-west-1 (Ireland)"}},
	"aws-prod-portal-001":       {{"value": "eu-west-1", "label": "eu-west-1 (Ireland)"}, {"value": "us-east-1", "label": "us-east-1 (N. Virginia)"}},
	"aws-nonprod-portal-002":    {{"value": "eu-west-1", "label": "eu-west-1 (Ireland)"}},
	"aws-prod-fraud-001":        {{"value": "eu-west-2", "label": "eu-west-2 (London)"}, {"value": "eu-central-1", "label": "eu-central-1 (Frankfurt)"}},
	"aws-prod-reporting-001":    {{"value": "eu-west-1", "label": "eu-west-1 (Ireland)"}},
	"aws-nonprod-reporting-002": {{"value": "eu-west-1", "label": "eu-west-1 (Ireland)"}},
}

type securityGroup struct {
	Value         string `json:"value"`
	Label         string `json:"label"`
	SgName        string `json:"sgName"`
	SgDescription string `json:"sgDescription"`
	SysidID       string `json:"-"`
	AccountID     string `json:"-"`
	Region        string `json:"-"`
}

var securityGroups = []securityGroup{
	{Value: "sg-0a1b2c3d4e5f", Label: "sg-0a1b2c3d4e5f — payments-app-sg", SgName: "payments-app-sg", SgDescription: "Main SG for Payments Gateway application tier", SysidID: "SYSID-10001", AccountID: "aws-prod-payments-001", Region: "eu-west-1"},
	{Value: "sg-1b2c3d4e5f6a", Label: "sg-1b2c3d4e5f6a — payments-db-sg", SgName: "payments-db-sg", SgDescription: "Database SG for Payments Gateway data tier", SysidID: "SYSID-10001", AccountID: "aws-prod-payments-001", Region: "eu-west-1"},
	{Value: "sg-2c3d4e5f6a7b", Label: "sg-2c3d4e5f6a7b — portal-app-sg", SgName: "portal-app-sg", SgDescription: "Main SG for Customer Portal application tier", SysidID: "SYSID-10002", AccountID: "aws-prod-portal-001", Region: "eu-west-1"},
	{Value: "sg-3d4e5f6a7b8c", Label: "sg-3d4e5f6a7b8c — fraud-app-sg", SgName: "fraud-app-sg", SgDescription: "Main SG for Fraud Detection service", SysidID: "SYSID-10003", AccountID: "aws-prod-fraud-001", Region: "eu-west-2"},
	{Value: "sg-4e5f6a7b8c9d", Label: "sg-4e5f6a7b8c9d — reporting-app-sg", SgName: "reporting-app-sg", SgDescription: "Main SG for Reporting Engine service", SysidID: "SYSID-10004", AccountID: "aws-prod-reporting-001", Region: "eu-west-1"},
}

var rulesBySG = map[string]string{
	"sg-0a1b2c3d4e5f": "sgr-001 | Inbound  | TCP | 443       | 0.0.0.0/0         | HTTPS from internet\nsgr-002 | Inbound  | TCP | 80        | 0.0.0.0/0         | HTTP redirect\nsgr-003 | Inbound  | TCP | 22        | 10.100.0.0/16     | SSH from VPN\nsgr-004 | Outbound | All | All       | 0.0.0.0/0         | All outbound",
	"sg-1b2c3d4e5f6a": "sgr-011 | Inbound  | TCP | 5432      | 10.100.10.0/24    | PostgreSQL from app tier\nsgr-012 | Outbound | All | All       | 0.0.0.0/0         | All outbound",
	"sg-2c3d4e5f6a7b": "sgr-021 | Inbound  | TCP | 443       | 0.0.0.0/0         | HTTPS from internet\nsgr-022 | Inbound  | TCP | 8080      | sg-0a1b2c3d4e5f   | From payments SG\nsgr-023 | Outbound | All | All       | 0.0.0.0/0         | All outbound",
	"sg-3d4e5f6a7b8c": "sgr-031 | Inbound  | TCP | 443       | 10.0.0.0/8        | Internal HTTPS only\nsgr-032 | Inbound  | TCP | 9090      | 10.0.0.0/8        | Metrics endpoint\nsgr-033 | Outbound | All | All       | 0.0.0.0/0         | All outbound",
	"sg-4e5f6a7b8c9d": "sgr-041 | Inbound  | TCP | 443       | 10.0.0.0/8        | Internal HTTPS\nsgr-042 | Outbound | TCP | 5432      | 10.100.20.0/24    | To reporting DB\nsgr-043 | Outbound | All | All       | 0.0.0.0/0         | All outbound",
}

var ruleCountBySG = map[string]string{
	"sg-0a1b2c3d4e5f": "4 rules active",
	"sg-1b2c3d4e5f6a": "2 rules active",
	"sg-2c3d4e5f6a7b": "3 rules active",
	"sg-3d4e5f6a7b8c": "3 rules active",
	"sg-4e5f6a7b8c9d": "3 rules active",
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func ok(c *gin.Context, data interface{}) {
	c.JSON(http.StatusOK, gin.H{"code": "000", "data": data})
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

// GET /sysids
func handleSysids(c *gin.Context) {
	var result []map[string]string
	for _, s := range sysids {
		result = append(result, map[string]string{
			"value": s.Value,
			"label": s.Label,
		})
	}
	ok(c, result)
}

// GET /sysid/:sysidId/details
func handleSysidDetails(c *gin.Context) {
	id := c.Param("sysidId")
	for _, s := range sysids {
		if s.Value == id {
			c.JSON(http.StatusOK, []map[string]string{{
				"value":         s.Value,
				"label":         s.SysidName,
				"sysidName":     s.SysidName,
				"sysidTier":     s.SysidTier,
				"reviewerGroup": s.ReviewerGroup,
			}})
			return
		}
	}
	c.JSON(http.StatusOK, []map[string]string{})
}

// GET /sysid/:sysidId/reviewer-check?owner=email
func handleReviewerCheck(c *gin.Context) {
	id := strings.ToLower(c.Param("sysidId"))
	owner := strings.ToLower(c.Query("owner"))
	groupName := fmt.Sprintf("dso-%s-reviewer", strings.ToLower(id))

	for _, email := range reviewerEmails {
		if strings.ToLower(email) == owner {
			c.JSON(http.StatusOK, []map[string]string{{
				"value":        "yes",
				"label":        "Access confirmed",
				"accessStatus": "yes",
				"reviewerGroup": groupName,
			}})
			return
		}
	}
	// No access — return empty array (form submit button stays disabled)
	c.JSON(http.StatusOK, []map[string]string{})
}

// GET /sysid/:sysidId/accounts
func handleAccounts(c *gin.Context) {
	id := c.Param("sysidId")
	accounts, ok2 := accountsBySysid[id]
	if !ok2 {
		c.JSON(http.StatusOK, []map[string]string{})
		return
	}
	c.JSON(http.StatusOK, accounts)
}

// GET /accounts/:accountId/regions
func handleRegions(c *gin.Context) {
	accountID := c.Param("accountId")
	regions, ok2 := regionsByAccount[accountID]
	if !ok2 {
		c.JSON(http.StatusOK, []map[string]string{})
		return
	}
	c.JSON(http.StatusOK, regions)
}

// GET /sysid/:sysidId/security-groups?account=&region=
func handleSecurityGroups(c *gin.Context) {
	sysidID := c.Param("sysidId")
	account := c.Query("account")
	region := c.Query("region")

	// Return empty when params are missing — avoids 4xx during cascade loading
	if sysidID == "" || account == "" || region == "" {
		c.JSON(http.StatusOK, []map[string]string{})
		return
	}

	var result []map[string]string
	for _, sg := range securityGroups {
		if sg.SysidID == sysidID && sg.AccountID == account && sg.Region == region {
			result = append(result, map[string]string{
				"value":         sg.Value,
				"label":         sg.Label,
				"sgName":        sg.SgName,
				"sgDescription": sg.SgDescription,
			})
		}
	}
	if result == nil {
		result = []map[string]string{}
	}
	c.JSON(http.StatusOK, result)
}

// GET /security-groups/:sgId/rules
// Returns single-item array for SelectFieldFromApi setContextData
func handleRules(c *gin.Context) {
	sgID := c.Param("sgId")
	summary, ok2 := rulesBySG[sgID]
	count, ok3 := ruleCountBySG[sgID]
	if !ok2 || !ok3 {
		c.JSON(http.StatusOK, []map[string]string{{
			"value":        "loaded",
			"label":        "0 rules active",
			"ruleCount":    "0 rules active",
			"rulesSummary": "(no rules configured)",
		}})
		return
	}
	c.JSON(http.StatusOK, []map[string]string{{
		"value":        "loaded",
		"label":        count,
		"ruleCount":    count,
		"rulesSummary": summary,
	}})
}

// POST /security-groups/:sgId/change-request
// Accepts full change payload, returns RITM number and URL
func handleChangeRequest(c *gin.Context) {
	sgID := c.Param("sgId")

	var body map[string]interface{}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": "400", "message": "invalid request body"})
		return
	}

	// Generate mock RITM number
	ritmNumber := fmt.Sprintf("RITM%07d", time.Now().UnixMilli()%9999999)
	ritmURL := fmt.Sprintf("https://servicenow.example.com/nav_to.do?uri=sc_req_item.do?number=%s", ritmNumber)

	log.Printf("Change request for SG %s: RITM %s | payload keys: %v", sgID, ritmNumber, func() []string {
		keys := make([]string, 0, len(body))
		for k := range body {
			keys = append(keys, k)
		}
		return keys
	}())

	c.JSON(http.StatusCreated, gin.H{
		"code":       "000",
		"ritmNumber": ritmNumber,
		"ritmUrl":    ritmURL,
		"message":    "Change request raised successfully",
	})
}

// ─── Main ─────────────────────────────────────────────────────────────────────

func main() {
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()

	// All routes under /hoover-service/security-groups/mock-api
	base := r.Group("/hoover-service/security-groups/mock-api")
	{
		base.GET("/sysids", handleSysids)
		base.GET("/sysid/:sysidId/details", handleSysidDetails)
		base.GET("/sysid/:sysidId/reviewer-check", handleReviewerCheck)
		base.GET("/sysid/:sysidId/accounts", handleAccounts)
		base.GET("/accounts/:accountId/regions", handleRegions)
		base.GET("/sysid/:sysidId/security-groups", handleSecurityGroups)
		base.GET("/security-groups/:sgId/rules", handleRules)
		base.POST("/security-groups/:sgId/change-request", handleChangeRequest)
	}

	port := ":8084"
	log.Printf("Security Groups mock API listening on %s", port)
	log.Printf("Test reviewer emails: %v", reviewerEmails)
	if err := r.Run(port); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
