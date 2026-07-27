package main

import (
	"context"
	"os"
	"path/filepath"

	"github.com/sagernet/sing-box/adapter"
	convertor "github.com/sagernet/sing-box/common/convertor/ruleset"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/route/rule"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/spf13/cobra"
)

var flagRuleSetMatchFormat string

var commandRuleSetMatch = &cobra.Command{
	Use:   "match <rule-set path> <IP address/domain>",
	Short: "Check if an IP address or a domain matches the rule-set",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		err := ruleSetMatch(args[0], args[1])
		if err != nil {
			log.Fatal(err)
		}
	},
}

func init() {
	commandRuleSetMatch.Flags().StringVarP(&flagRuleSetMatchFormat, "format", "f", "", "rule-set format")
	commandRuleSet.AddCommand(commandRuleSetMatch)
}

func ruleSetMatch(sourcePath string, domain string) error {
	var reader *os.File
	var err error
	if sourcePath == "stdin" {
		reader = os.Stdin
	} else {
		reader, err = os.Open(sourcePath)
		if err != nil {
			return E.Cause(err, "read rule-set")
		}
		defer reader.Close()
	}
	if flagRuleSetMatchFormat == "" {
		switch filepath.Ext(sourcePath) {
		case ".json":
			flagRuleSetMatchFormat = C.RuleSetFormatSource
		case ".srs":
			flagRuleSetMatchFormat = C.RuleSetFormatBinary
		case ".txt":
			flagRuleSetMatchFormat = C.RuleSetFormatText
		case ".yaml", ".yml":
			flagRuleSetMatchFormat = C.RuleSetFormatYAML
		}
		if flagRuleSetMatchFormat == "" {
			flagRuleSetMatchFormat = C.RuleSetFormatAuto
		}
	}
	plainRuleSet, _, err := convertor.Read(reader, flagRuleSetMatchFormat)
	if err != nil {
		return err
	}
	ipAddress := M.ParseAddr(domain)
	var metadata adapter.InboundContext
	if ipAddress.IsValid() {
		metadata.Destination = M.SocksaddrFrom(ipAddress, 0)
	} else {
		metadata.Domain = domain
	}
	for i, ruleOptions := range plainRuleSet.Rules {
		var currentRule adapter.HeadlessRule
		currentRule, err = rule.NewHeadlessRule(context.Background(), ruleOptions)
		if err != nil {
			return E.Cause(err, "parse rule_set.rules.[", i, "]")
		}
		if currentRule.Match(&metadata) {
			println(F.ToString("match rules.[", i, "]: ", currentRule))
		}
	}
	return nil
}
