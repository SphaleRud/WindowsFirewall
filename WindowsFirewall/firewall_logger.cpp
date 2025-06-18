#include "firewall_logger.h"
#include <Windows.h>

// Example usage functions
void LogFirewallRuleChange(const std::string& ruleName,
    const std::string& previousValue,
    const std::string& newValue) {
    FirewallEvent event;
    event.type = FirewallEventType::RULE_MODIFIED;
    event.ruleName = ruleName;
    event.previousValue = previousValue;
    event.newValue = newValue;
    event.username = FirewallLogger::Instance().GetCurrentUsername();

    FirewallLogger::Instance().LogRuleEvent(event);
}

void LogServiceStart() {
    FirewallLogger::Instance().LogServiceEvent(
        FirewallEventType::SERVICE_STARTED,
        "Firewall service started successfully"
    );
}

void LogServiceStop() {
    FirewallLogger::Instance().LogServiceEvent(
        FirewallEventType::FIREWALL_SERVICE_STOPPED,
        "Firewall service stopped successfully"
    );
}

void LogPacketCaptureStart() {
    FirewallLogger::Instance().LogServiceEvent(
        FirewallEventType::CAPTURE_STARTED,
        "Packet capture started"
    );
}

void LogPacketCaptureStop() {
    FirewallLogger::Instance().LogServiceEvent(
        FirewallEventType::CAPTURE_STOPPED,
        "Packet capture stopped"
    );
}