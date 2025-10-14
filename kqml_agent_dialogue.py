"""
================================================================================
KQML/KIF AGENT DIALOGUE SYSTEM
================================================================================
This script demonstrates agent communication using:
- KQML (Knowledge Query and Manipulation Language) for communication acts
- KIF (Knowledge Interchange Format) for knowledge representation

Agents:
- Alice: Procurement agent (queries stock availability)
- Bob: Warehouse inventory agent (manages stock information)

Learning Outcomes:
- Understanding agent-based computing motivations
- Practical implementation of agent communication protocols
- Knowledge representation and interchange between autonomous agents

Author: Agent Systems Learning Module
Date: October 2025
================================================================================
"""

# ============================================================================
# IMPORTS
# ============================================================================
import json
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum

# ============================================================================
# KQML PERFORMATIVE TYPES
# ============================================================================
class KQMLPerformative(Enum):
    """
    KQML Performatives define the type of communicative act.
    
    Common KQML performatives include:
    - ASK_IF: Ask whether a statement is true
    - ASK_ONE: Ask for one answer to a query
    - ASK_ALL: Ask for all answers to a query
    - TELL: Inform another agent of a fact
    - REPLY: Reply to a previous query
    - SUBSCRIBE: Subscribe to updates about certain information
    - ADVERTISE: Advertise capabilities
    """
    ASK_IF = "ask-if"          # Query whether something is true
    ASK_ONE = "ask-one"        # Query for one answer
    ASK_ALL = "ask-all"        # Query for all answers
    TELL = "tell"              # Assert a fact
    REPLY = "reply"            # Reply to a query
    SORRY = "sorry"            # Unable to process request
    ADVERTISE = "advertise"    # Advertise capabilities
    SUBSCRIBE = "subscribe"    # Subscribe to information updates

# ============================================================================
# KIF KNOWLEDGE REPRESENTATION
# ============================================================================
class KIFExpression:
    """
    KIF (Knowledge Interchange Format) is a formal language for representing
    knowledge in a way that can be shared between different systems.
    
    KIF uses predicate logic with predicates like:
    - (stock-level ?item ?quantity)
    - (has-property ?item ?property ?value)
    - (available ?item)
    """
    
    @staticmethod
    def predicate(name: str, *args) -> str:
        """
        Create a KIF predicate expression.
        
        Args:
            name: Predicate name
            *args: Arguments to the predicate
            
        Returns:
            KIF formatted predicate string
            
        Example:
            predicate("stock-level", "tv-50inch", "?quantity")
            Returns: "(stock-level tv-50inch ?quantity)"
        """
        args_str = " ".join(str(arg) for arg in args)
        return f"({name} {args_str})"
    
    @staticmethod
    def and_expression(*predicates) -> str:
        """
        Create a KIF AND expression (conjunction).
        
        Args:
            *predicates: Multiple predicates to combine with AND
            
        Returns:
            KIF formatted AND expression
            
        Example:
            and_expression("(available tv)", "(stock-level tv 10)")
            Returns: "(and (available tv) (stock-level tv 10))"
        """
        preds_str = " ".join(predicates)
        return f"(and {preds_str})"
    
    @staticmethod
    def exists(variable: str, expression: str) -> str:
        """
        Create a KIF existential quantification.
        
        Args:
            variable: Variable name (e.g., "?x")
            expression: Expression containing the variable
            
        Returns:
            KIF formatted exists expression
        """
        return f"(exists ({variable}) {expression})"

# ============================================================================
# KQML MESSAGE STRUCTURE
# ============================================================================
@dataclass
class KQMLMessage:
    """
    Represents a KQML message exchanged between agents.
    
    A KQML message consists of:
    - performative: Type of communicative act (ask, tell, reply, etc.)
    - sender: Agent sending the message
    - receiver: Agent receiving the message
    - content: The actual content (often in KIF format)
    - reply_with: Identifier for tracking conversations
    - in_reply_to: Reference to message being replied to
    - language: Content language (typically KIF)
    - ontology: Domain ontology being used
    """
    performative: KQMLPerformative
    sender: str
    receiver: str
    content: str
    reply_with: Optional[str] = None
    in_reply_to: Optional[str] = None
    language: str = "KIF"
    ontology: str = "warehouse-inventory"
    timestamp: str = None
    
    def __post_init__(self):
        """Set timestamp if not provided."""
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()
    
    def to_kqml_string(self) -> str:
        """
        Convert the message to KQML format string.
        
        KQML format example:
        (ask-one
          :sender Alice
          :receiver Bob
          :content "(stock-level tv-50inch ?quantity)"
          :reply-with msg-001
          :language KIF
          :ontology warehouse-inventory)
        
        Returns:
            Formatted KQML string
        """
        lines = [f"({self.performative.value}"]
        lines.append(f"  :sender {self.sender}")
        lines.append(f"  :receiver {self.receiver}")
        lines.append(f"  :content \"{self.content}\"")
        
        if self.reply_with:
            lines.append(f"  :reply-with {self.reply_with}")
        if self.in_reply_to:
            lines.append(f"  :in-reply-to {self.in_reply_to}")
        
        lines.append(f"  :language {self.language}")
        lines.append(f"  :ontology {self.ontology}")
        lines.append(")")
        
        return "\n".join(lines)
    
    def __str__(self) -> str:
        """String representation for display."""
        return self.to_kqml_string()

# ============================================================================
# PRODUCT DATABASE (KNOWLEDGE BASE)
# ============================================================================
class ProductDatabase:
    """
    Simulates a warehouse inventory database.
    
    This represents Bob's knowledge base containing information about
    products, their properties, and stock levels.
    """
    
    def __init__(self):
        """Initialize the product database with sample inventory."""
        # Database structure: product_id -> properties
        self.inventory = {
            "tv-50inch-samsung": {
                "type": "television",
                "brand": "Samsung",
                "size": "50inch",
                "hdmi_slots": 4,
                "stock_level": 15,
                "available": True,
                "price": 599.99
            },
            "tv-50inch-lg": {
                "type": "television",
                "brand": "LG",
                "size": "50inch",
                "hdmi_slots": 3,
                "stock_level": 8,
                "available": True,
                "price": 549.99
            },
            "tv-50inch-sony": {
                "type": "television",
                "brand": "Sony",
                "size": "50inch",
                "hdmi_slots": 4,
                "stock_level": 0,
                "available": False,
                "price": 649.99
            }
        }
    
    def query_stock_level(self, product_id: str) -> Optional[int]:
        """
        Query the stock level for a specific product.
        
        Args:
            product_id: Product identifier
            
        Returns:
            Stock level or None if product not found
        """
        if product_id in self.inventory:
            return self.inventory[product_id]["stock_level"]
        return None
    
    def query_property(self, product_id: str, property_name: str) -> Optional[Any]:
        """
        Query a specific property of a product.
        
        Args:
            product_id: Product identifier
            property_name: Name of property to query
            
        Returns:
            Property value or None if not found
        """
        if product_id in self.inventory:
            return self.inventory[product_id].get(property_name)
        return None
    
    def query_products_by_criteria(self, **criteria) -> List[Dict]:
        """
        Query products matching specific criteria.
        
        Args:
            **criteria: Key-value pairs for filtering products
            
        Returns:
            List of matching products with their properties
        """
        matching_products = []
        
        for product_id, properties in self.inventory.items():
            match = True
            for key, value in criteria.items():
                if properties.get(key) != value:
                    match = False
                    break
            
            if match:
                product_info = {"product_id": product_id, **properties}
                matching_products.append(product_info)
        
        return matching_products

# ============================================================================
# AGENT BASE CLASS
# ============================================================================
class Agent:
    """
    Base class for intelligent agents.
    
    An agent is an autonomous entity that:
    - Perceives its environment (receives messages)
    - Reasons about information (processes queries)
    - Acts to achieve goals (sends messages)
    - Communicates with other agents (KQML/KIF)
    """
    
    def __init__(self, name: str):
        """
        Initialize an agent.
        
        Args:
            name: Unique identifier for the agent
        """
        self.name = name
        self.message_counter = 0
        self.conversation_history: List[KQMLMessage] = []
    
    def generate_message_id(self) -> str:
        """
        Generate a unique message identifier.
        
        Returns:
            Message ID string (e.g., "alice-msg-001")
        """
        self.message_counter += 1
        return f"{self.name.lower()}-msg-{self.message_counter:03d}"
    
    def send_message(self, message: KQMLMessage) -> None:
        """
        Send a message to another agent.
        
        Args:
            message: KQML message to send
        """
        self.conversation_history.append(message)
        print(f"\n{'='*70}")
        print(f"[{self.name} → {message.receiver}] @ {message.timestamp}")
        print('='*70)
        print(message.to_kqml_string())
        print()
    
    def receive_message(self, message: KQMLMessage) -> Optional[KQMLMessage]:
        """
        Receive and process a message from another agent.
        
        Args:
            message: Received KQML message
            
        Returns:
            Response message or None
        """
        self.conversation_history.append(message)
        return None

# ============================================================================
# ALICE AGENT (PROCUREMENT AGENT)
# ============================================================================
class AliceAgent(Agent):
    """
    Alice is a procurement agent responsible for:
    - Querying stock availability
    - Checking product specifications
    - Making purchase decisions based on requirements
    
    Alice uses KQML to communicate queries and KIF to express knowledge needs.
    """
    
    def __init__(self):
        """Initialize Alice procurement agent."""
        super().__init__("Alice")
        self.required_hdmi_slots = 4  # Business requirement
    
    def ask_about_50inch_tv_stock(self, receiver: str) -> KQMLMessage:
        """
        Query Bob about available 50-inch televisions.
        
        This uses ASK-ALL performative to get all matching products.
        KIF content expresses: "Tell me all 50-inch TVs that are available"
        
        Args:
            receiver: Name of receiving agent (Bob)
            
        Returns:
            KQML message with query
        """
        # KIF expression: Query for all 50-inch TVs with availability and stock level
        kif_content = KIFExpression.and_expression(
            KIFExpression.predicate("type", "?product", "television"),
            KIFExpression.predicate("size", "?product", "50inch"),
            KIFExpression.predicate("available", "?product", "true"),
            KIFExpression.predicate("stock-level", "?product", "?quantity")
        )
        
        message = KQMLMessage(
            performative=KQMLPerformative.ASK_ALL,
            sender=self.name,
            receiver=receiver,
            content=kif_content,
            reply_with=self.generate_message_id()
        )
        
        return message
    
    def ask_about_hdmi_slots(self, receiver: str, product_id: str, 
                            in_reply_to: str) -> KQMLMessage:
        """
        Query Bob about HDMI slots for a specific product.
        
        This uses ASK-ONE performative to get a single answer.
        KIF content expresses: "How many HDMI slots does this product have?"
        
        Args:
            receiver: Name of receiving agent (Bob)
            product_id: Specific product to query
            in_reply_to: Message ID this is responding to
            
        Returns:
            KQML message with query
        """
        # KIF expression: Query for HDMI slots of specific product
        kif_content = KIFExpression.predicate(
            "hdmi-slots", 
            product_id, 
            "?num_slots"
        )
        
        message = KQMLMessage(
            performative=KQMLPerformative.ASK_ONE,
            sender=self.name,
            receiver=receiver,
            content=kif_content,
            reply_with=self.generate_message_id(),
            in_reply_to=in_reply_to
        )
        
        return message
    
    def evaluate_product(self, product_info: Dict) -> bool:
        """
        Evaluate whether a product meets procurement requirements.
        
        Args:
            product_info: Product specifications
            
        Returns:
            True if product meets requirements, False otherwise
        """
        hdmi_slots = product_info.get("hdmi_slots", 0)
        stock_level = product_info.get("stock_level", 0)
        
        return hdmi_slots >= self.required_hdmi_slots and stock_level > 0

# ============================================================================
# BOB AGENT (WAREHOUSE INVENTORY AGENT)
# ============================================================================
class BobAgent(Agent):
    """
    Bob is a warehouse inventory agent responsible for:
    - Managing product database
    - Responding to stock queries
    - Providing product specifications
    - Maintaining inventory knowledge base
    
    Bob processes KQML queries and responds with KIF-formatted answers.
    """
    
    def __init__(self):
        """Initialize Bob inventory agent with product database."""
        super().__init__("Bob")
        self.database = ProductDatabase()
    
    def receive_message(self, message: KQMLMessage) -> Optional[KQMLMessage]:
        """
        Process incoming messages and generate appropriate responses.
        
        Args:
            message: Received KQML message
            
        Returns:
            Response message based on query type
        """
        super().receive_message(message)
        
        # Route message based on performative type
        if message.performative == KQMLPerformative.ASK_ALL:
            return self.handle_ask_all(message)
        elif message.performative == KQMLPerformative.ASK_ONE:
            return self.handle_ask_one(message)
        else:
            # Return SORRY performative for unsupported message types
            return KQMLMessage(
                performative=KQMLPerformative.SORRY,
                sender=self.name,
                receiver=message.sender,
                content="(unsupported-performative)",
                in_reply_to=message.reply_with
            )
    
    def handle_ask_all(self, message: KQMLMessage) -> KQMLMessage:
        """
        Handle ASK-ALL queries by searching database for all matching items.
        
        Args:
            message: Query message
            
        Returns:
            REPLY message with all matching results in KIF format
        """
        # Parse query to extract criteria
        # In a full implementation, would parse KIF content
        # For this demo, we know Alice is asking about 50-inch TVs
        
        products = self.database.query_products_by_criteria(
            type="television",
            size="50inch",
            available=True
        )
        
        # Format response in KIF
        if products:
            # Build KIF response with all matching products
            product_statements = []
            for product in products:
                product_id = product["product_id"]
                stock = product["stock_level"]
                brand = product["brand"]
                
                statement = KIFExpression.and_expression(
                    KIFExpression.predicate("product-id", product_id),
                    KIFExpression.predicate("brand", brand),
                    KIFExpression.predicate("stock-level", product_id, stock),
                    KIFExpression.predicate("available", product_id, "true")
                )
                product_statements.append(statement)
            
            # Combine all product statements
            kif_response = " ".join(product_statements)
        else:
            kif_response = "(no-matching-products)"
        
        response = KQMLMessage(
            performative=KQMLPerformative.REPLY,
            sender=self.name,
            receiver=message.sender,
            content=kif_response,
            in_reply_to=message.reply_with
        )
        
        return response
    
    def handle_ask_one(self, message: KQMLMessage) -> KQMLMessage:
        """
        Handle ASK-ONE queries by finding single answer from database.
        
        Args:
            message: Query message
            
        Returns:
            REPLY message with answer in KIF format
        """
        # Parse query to extract product ID and property
        # In this demo, we extract from the KIF content pattern
        content = message.content
        
        # Simple parsing: extract product ID
        # Format: "(hdmi-slots product-id ?num_slots)"
        if "hdmi-slots" in content:
            # Extract product ID from between first and second space
            parts = content.strip("()").split()
            if len(parts) >= 2:
                product_id = parts[1]
                
                # Query database
                hdmi_slots = self.database.query_property(
                    product_id, 
                    "hdmi_slots"
                )
                
                if hdmi_slots is not None:
                    # Format response in KIF
                    kif_response = KIFExpression.predicate(
                        "hdmi-slots",
                        product_id,
                        hdmi_slots
                    )
                else:
                    kif_response = "(unknown-product)"
            else:
                kif_response = "(invalid-query)"
        else:
            kif_response = "(unsupported-query)"
        
        response = KQMLMessage(
            performative=KQMLPerformative.REPLY,
            sender=self.name,
            receiver=message.sender,
            content=kif_response,
            in_reply_to=message.reply_with
        )
        
        return response

# ============================================================================
# DIALOGUE COORDINATOR
# ============================================================================
class DialogueCoordinator:
    """
    Coordinates the conversation between Alice and Bob.
    
    This simulates a multi-agent system where agents exchange messages
    to accomplish their goals through collaboration.
    """
    
    def __init__(self):
        """Initialize the dialogue coordinator."""
        self.alice = AliceAgent()
        self.bob = BobAgent()
        self.all_messages: List[KQMLMessage] = []
    
    def deliver_message(self, sender: Agent, message: KQMLMessage, 
                       receiver: Agent) -> Optional[KQMLMessage]:
        """
        Deliver a message from sender to receiver and get response.
        
        Args:
            sender: Sending agent
            message: Message to deliver
            receiver: Receiving agent
            
        Returns:
            Response message or None
        """
        # Sender sends message
        sender.send_message(message)
        self.all_messages.append(message)
        
        # Receiver processes message and generates response
        response = receiver.receive_message(message)
        
        if response:
            # Receiver sends response
            receiver.send_message(response)
            self.all_messages.append(response)
        
        return response
    
    def run_dialogue(self) -> None:
        """
        Execute the complete dialogue scenario between Alice and Bob.
        
        Scenario:
        1. Alice asks Bob about available 50-inch TVs
        2. Bob replies with available inventory
        3. Alice asks about HDMI slots for specific products
        4. Bob replies with specifications
        5. Alice evaluates and makes decision
        """
        print("\n" + "="*70)
        print("AGENT DIALOGUE SIMULATION: ALICE AND BOB")
        print("Scenario: Stock Procurement Query")
        print("="*70)
        
        # ====================================================================
        # STEP 1: Alice queries Bob about 50-inch TV availability
        # ====================================================================
        print("\n[STEP 1] Alice queries available 50-inch televisions...")
        
        msg1 = self.alice.ask_about_50inch_tv_stock("Bob")
        response1 = self.deliver_message(self.alice, msg1, self.bob)
        
        # ====================================================================
        # STEP 2: Alice processes Bob's response
        # ====================================================================
        print("\n[STEP 2] Alice processes inventory information...")
        
        if response1 and response1.performative == KQMLPerformative.REPLY:
            # Parse response to extract product IDs
            # In this demo, we'll directly access Bob's database
            available_products = self.bob.database.query_products_by_criteria(
                type="television",
                size="50inch",
                available=True
            )
            
            print(f"\nAlice found {len(available_products)} available product(s)")
            
            # ================================================================
            # STEP 3: Alice queries HDMI slots for each product
            # ================================================================
            print("\n[STEP 3] Alice queries HDMI specifications...")
            
            for product in available_products:
                product_id = product["product_id"]
                
                # Ask about HDMI slots
                msg_hdmi = self.alice.ask_about_hdmi_slots(
                    "Bob", 
                    product_id,
                    response1.reply_with or ""
                )
                response_hdmi = self.deliver_message(
                    self.alice, 
                    msg_hdmi, 
                    self.bob
                )
                
                # Evaluate product
                if self.alice.evaluate_product(product):
                    print(f"\n✓ {product_id} meets requirements!")
                    print(f"  - Brand: {product['brand']}")
                    print(f"  - HDMI Slots: {product['hdmi_slots']}")
                    print(f"  - Stock Level: {product['stock_level']}")
                    print(f"  - Price: ${product['price']}")
                else:
                    print(f"\n✗ {product_id} does not meet requirements")
                    print(f"  - HDMI Slots: {product['hdmi_slots']} " +
                          f"(Required: {self.alice.required_hdmi_slots})")
        
        # ====================================================================
        # SUMMARY
        # ====================================================================
        print("\n" + "="*70)
        print("DIALOGUE SUMMARY")
        print("="*70)
        print(f"Total messages exchanged: {len(self.all_messages)}")
        print(f"Alice sent: {len(self.alice.conversation_history)} messages")
        print(f"Bob sent: {len(self.bob.conversation_history)} messages")
        print("\nDialogue completed successfully!")
        print("="*70)

# ============================================================================
# MAIN EXECUTION
# ============================================================================
def main():
    """
    Main function to run the agent dialogue simulation.
    """
    # Create dialogue coordinator and run simulation
    coordinator = DialogueCoordinator()
    coordinator.run_dialogue()
    
    print("\n" + "="*70)
    print("LEARNING OUTCOMES DEMONSTRATED")
    print("="*70)
    print("""
✓ Agent-Based Computing Motivations:
  - Autonomous decision making (Alice evaluates products)
  - Distributed knowledge (Bob maintains inventory database)
  - Communication and coordination between independent agents
  - Goal-oriented behavior (procurement task completion)

✓ Agent Communication Standards:
  - KQML for message structure and speech acts
  - KIF for knowledge representation
  - Asynchronous message passing
  - Conversation tracking with reply-with/in-reply-to

✓ Agent Models:
  - Reactive agents (Bob responds to queries)
  - Deliberative agents (Alice reasons about requirements)
  - Knowledge-based agents (both use structured databases)
  - Collaborative multi-agent systems
    """)

if __name__ == "__main__":
    main()

# ============================================================================
# END OF SCRIPT
# ============================================================================
"""
ADDITIONAL NOTES:
-----------------
1. KQML (Knowledge Query and Manipulation Language):
   - Developed in early 1990s for agent communication
   - Defines performatives (speech acts) for inter-agent messages
   - Widely used in multi-agent systems research

2. KIF (Knowledge Interchange Format):
   - First-order logic based knowledge representation
   - Allows agents to share knowledge in a common format
   - Platform and language independent

3. This implementation demonstrates:
   - Agent autonomy and goal-directed behavior
   - Standard communication protocols
   - Knowledge representation and reasoning
   - Multi-agent coordination

4. Real-world applications:
   - Supply chain management
   - E-commerce systems
   - Distributed resource allocation
   - Information retrieval systems
"""