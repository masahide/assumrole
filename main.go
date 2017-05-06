package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
)

var (
	// Version is version number
	Version = "dev"
	// Date is build date
	Date            string
	roleArn         string
	roleSessionName string
	durationSeconds = 3600
	externalID      string
	policy          string
	serialNumber    string
	tokenCode       string
	showResult      bool
	showVer         bool
)

func init() {
	flag.BoolVar(&showResult, "show", showResult, "show result")
	flag.StringVar(&roleArn, "roleArn", roleArn, "role arn Ex:'arn:aws:iam::123456789012:role/role-name'")
	flag.StringVar(&roleSessionName, "roleSessionName", roleSessionName, "role session name")
	flag.IntVar(&durationSeconds, "durationSec", durationSeconds, "duration: 900-3600")
	flag.StringVar(&externalID, "externalId", externalID, "external ID")
	flag.StringVar(&policy, "policy", policy, " IAM policy in JSON format.")
	flag.StringVar(&serialNumber, "serialNumber", serialNumber, "The identification number of the MFA device that is associated with the user who is making the call.")
	flag.StringVar(&tokenCode, "tokencode", tokenCode, "The value provided by the MFA device, if the trust policy of the role being assumed requires MFA.")
	flag.BoolVar(&showVer, "version", showVer, "Show version")
	flag.Parse()
}

func nilString(s string) *string {
	if s != "" {
		return aws.String(s)
	}
	return nil
}

func main() {
	if showVer {
		fmt.Printf("version: %s %s\n", Version, Date)
		return
	}
	if roleArn == "" {
		log.Print("Require -role option.")
		flag.PrintDefaults()
		return
	}
	if roleSessionName == "" {
		index := strings.LastIndex(roleArn, "/")
		roleName := roleArn[index+1:]
		roleSessionName = roleName + "-" + os.Getenv("USER")
	}
	params := &sts.AssumeRoleInput{
		RoleArn:         aws.String(roleArn),
		RoleSessionName: aws.String(roleSessionName),
		DurationSeconds: aws.Int64(int64(durationSeconds)),
		ExternalId:      nilString(externalID),
		Policy:          nilString(policy),
		SerialNumber:    nilString(serialNumber),
		TokenCode:       nilString(tokenCode),
	}

	sess := session.Must(session.NewSession())
	svc := sts.New(sess)
	resp, err := svc.AssumeRole(params)

	if err != nil {
		log.Fatal(err.Error())
	}

	if showResult {
		fmt.Println(resp) // Pretty-print the response data.
	} else {
		fmt.Printf(
			"AWS_ACCESS_KEY_ID=%s AWS_SECRET_ACCESS_KEY=%s AWS_SESSION_TOKEN=%s",
			*resp.Credentials.AccessKeyId,
			*resp.Credentials.SecretAccessKey,
			*resp.Credentials.SessionToken,
		)
	}
}
