#pragma once

// ��� ������� ������������ ��� ������ ��������
enum class Protocol {
    ANY,
    TCP,
    UDP,
    ICMP
};

enum class RuleAction {
    ALLOW,
    BLOCK
};

enum class RuleDirection {
    Inbound,
    Outbound
};

enum class PacketDirection {
    Incoming,
    Outgoing
};