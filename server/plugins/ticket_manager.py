from enum import Enum
class TicketManager:
    def __init__(self, ticket_state, current_status):
        self.ticket_state = ticket_state
        self.current_status = current_status
        self.transition_mappings = {
            ("FIXED", "Mitigated"): None,
            ("REOPENED", "Vulnerable"): None,  # No transition ID for this condition
            ("FIXED", "Vulnerable"): "41",
            ("REOPENED", "Mitigated"): "21"
        }

    def transition_ticket_status(self, current_state, new_state):
        transition_id = None
        transition_status = self.status_transitions.get((current_state, new_state))
        if transition_status:
            print(f"Transitioning from {current_state} to {new_state} with status: {transition_status}")
            # Perform other actions such as creating comments, sending requests, etc.
        else:
            print("Invalid transition")

    def transition_id(self):
        for state, status in self.transition_mappings.keys():
            if self.ticket_state == state and self.current_status != status:
                return self.transition_mappings[(state, status)]
        return None
