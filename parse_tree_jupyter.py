"""
================================================================================
CONSTITUENCY-BASED PARSE TREE GENERATOR - JUPYTER NOTEBOOK VERSION
================================================================================
This script demonstrates syntactic parsing in Natural Language Processing (NLP).
It creates and analyzes constituency-based parse trees for three example sentences,
including handling structural ambiguity.

INSTRUCTIONS FOR JUPYTER NOTEBOOK:
1. Install required packages: pip install nltk matplotlib
2. Run all cells in order
3. Uncomment visualization lines to see graphical trees

Author: NLP Learning Module
Purpose: Educational demonstration of parse tree structures
================================================================================
"""

# ============================================================================
# CELL 1: LIBRARY IMPORTS AND SETUP
# ============================================================================

import nltk
from nltk import Tree
from nltk.draw.tree import TreeView
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch
import matplotlib.patches as mpatches

# For Jupyter notebook display
from IPython.display import display, Image
import os

print("Libraries imported successfully!")

# ============================================================================
# CELL 2: DOWNLOAD REQUIRED NLTK DATA
# ============================================================================

# Download required NLTK data (only needs to run once)
try:
    nltk.data.find('tokenizers/punkt')
    print("✓ Punkt tokenizer already downloaded")
except LookupError:
    print("Downloading punkt tokenizer...")
    nltk.download('punkt')
    print("✓ Punkt tokenizer downloaded")

try:
    nltk.data.find('taggers/averaged_perceptron_tagger')
    print("✓ POS tagger already downloaded")
except LookupError:
    print("Downloading POS tagger...")
    nltk.download('averaged_perceptron_tagger')
    print("✓ POS tagger downloaded")

print("\n✓ All NLTK data ready!")

# ============================================================================
# CELL 3: MAIN CLASS DEFINITION - ParseTreeGenerator
# ============================================================================

class ParseTreeGenerator:
    """
    A class to generate and analyze constituency-based parse trees.
    
    This class creates manual parse trees for three sentences and provides
    methods to visualize and analyze their syntactic structure.
    
    Attributes:
        trees (dict): Dictionary containing all parse tree structures
    """
    
    def __init__(self):
        """
        Initialize the ParseTreeGenerator with predefined parse trees.
        
        Creates a dictionary containing four parse trees:
        - sentence1: "The government raised interest rates"
        - sentence2: "The internet gives everyone a voice"
        - sentence3_v1: "The man saw the dog with telescope" (interpretation 1)
        - sentence3_v2: "The man saw the dog with telescope" (interpretation 2)
        """
        self.trees = {
            "sentence1": self.create_tree1(),
            "sentence2": self.create_tree2(),
            "sentence3_v1": self.create_tree3_version1(),
            "sentence3_v2": self.create_tree3_version2()
        }
    
    # ========================================================================
    # TREE CREATION METHODS
    # ========================================================================
    
    def create_tree1(self):
        """
        Create parse tree for: "The government raised interest rates."
        
        Structure:
            S (Sentence)
            ├── NP (Subject: "The government")
            │   ├── DT: "The"
            │   └── NN: "government"
            └── VP (Predicate: "raised interest rates")
                ├── VBD: "raised"
                └── NP (Object: "interest rates")
                    ├── NN: "interest"
                    └── NNS: "rates"
        
        Returns:
            Tree: NLTK Tree object representing the parse structure
        """
        tree = Tree('S', [
            # Subject noun phrase
            Tree('NP', [
                Tree('DT', ['The']),        # Determiner
                Tree('NN', ['government'])  # Singular noun
            ]),
            # Verb phrase (predicate)
            Tree('VP', [
                Tree('VBD', ['raised']),    # Past tense verb
                # Object noun phrase (compound noun)
                Tree('NP', [
                    Tree('NN', ['interest']),   # Singular noun (modifier)
                    Tree('NNS', ['rates'])      # Plural noun (head)
                ])
            ])
        ])
        return tree
    
    def create_tree2(self):
        """
        Create parse tree for: "The internet gives everyone a voice."
        
        Structure:
            S (Sentence)
            ├── NP (Subject: "The internet")
            │   ├── DT: "The"
            │   └── NN: "internet"
            └── VP (Predicate: "gives everyone a voice")
                ├── VBZ: "gives"
                ├── NP (Indirect Object: "everyone")
                │   └── NN: "everyone"
                └── NP (Direct Object: "a voice")
                    ├── DT: "a"
                    └── NN: "voice"
        
        This is a ditransitive verb structure with both an indirect object
        (everyone) and a direct object (a voice).
        
        Returns:
            Tree: NLTK Tree object representing the parse structure
        """
        tree = Tree('S', [
            # Subject noun phrase
            Tree('NP', [
                Tree('DT', ['The']),      # Determiner
                Tree('NN', ['internet'])  # Singular noun
            ]),
            # Verb phrase (predicate) - ditransitive structure
            Tree('VP', [
                Tree('VBZ', ['gives']),   # 3rd person singular present verb
                # Indirect object (recipient)
                Tree('NP', [
                    Tree('NN', ['everyone'])  # Pronoun treated as noun
                ]),
                # Direct object (thing given)
                Tree('NP', [
                    Tree('DT', ['a']),      # Determiner
                    Tree('NN', ['voice'])   # Singular noun
                ])
            ])
        ])
        return tree
    
    def create_tree3_version1(self):
        """
        Create parse tree for: "The man saw the dog with the telescope."
        
        INTERPRETATION 1: PP attached to VP (instrument reading)
        Meaning: The man used the telescope to see the dog
        
        Structure:
            S (Sentence)
            ├── NP (Subject: "The man")
            │   ├── DT: "The"
            │   └── NN: "man"
            └── VP (Predicate: "saw the dog with the telescope")
                ├── VBD: "saw"
                ├── NP (Object: "the dog")
                │   ├── DT: "the"
                │   └── NN: "dog"
                └── PP (Instrument - modifies "saw")
                    ├── IN: "with"
                    └── NP: "the telescope"
                        ├── DT: "the"
                        └── NN: "telescope"
        
        The PP is attached at the VP level, indicating it modifies the verb "saw"
        (i.e., the telescope is the instrument used for seeing).
        
        Returns:
            Tree: NLTK Tree object representing the parse structure
        """
        tree = Tree('S', [
            # Subject noun phrase
            Tree('NP', [
                Tree('DT', ['The']),  # Determiner
                Tree('NN', ['man'])   # Singular noun
            ]),
            # Verb phrase (predicate)
            Tree('VP', [
                Tree('VBD', ['saw']),  # Past tense verb
                # Direct object
                Tree('NP', [
                    Tree('DT', ['the']),  # Determiner
                    Tree('NN', ['dog'])   # Singular noun
                ]),
                # Prepositional phrase (attached to VP - modifies verb)
                # This attachment means: "saw WITH the telescope"
                Tree('PP', [
                    Tree('IN', ['with']),  # Preposition
                    # Object of preposition
                    Tree('NP', [
                        Tree('DT', ['the']),       # Determiner
                        Tree('NN', ['telescope'])  # Singular noun
                    ])
                ])
            ])
        ])
        return tree
    
    def create_tree3_version2(self):
        """
        Create parse tree for: "The man saw the dog with the telescope."
        
        INTERPRETATION 2: PP attached to NP (possession reading)
        Meaning: The dog has the telescope, and the man saw that dog
        
        Structure:
            S (Sentence)
            ├── NP (Subject: "The man")
            │   ├── DT: "The"
            │   └── NN: "man"
            └── VP (Predicate: "saw the dog with the telescope")
                ├── VBD: "saw"
                └── NP (Complex Object: "the dog with the telescope")
                    ├── NP (Head: "the dog")
                    │   ├── DT: "the"
                    │   └── NN: "dog"
                    └── PP (Modifier - attached to NP)
                        ├── IN: "with"
                        └── NP: "the telescope"
                            ├── DT: "the"
                            └── NN: "telescope"
        
        The PP is attached at the NP level (inside the object NP), indicating
        it modifies the noun "dog" (i.e., the dog that has the telescope).
        
        Returns:
            Tree: NLTK Tree object representing the parse structure
        """
        tree = Tree('S', [
            # Subject noun phrase
            Tree('NP', [
                Tree('DT', ['The']),  # Determiner
                Tree('NN', ['man'])   # Singular noun
            ]),
            # Verb phrase (predicate)
            Tree('VP', [
                Tree('VBD', ['saw']),  # Past tense verb
                # Complex direct object (NP with PP modifier)
                Tree('NP', [
                    # Core noun phrase
                    Tree('NP', [
                        Tree('DT', ['the']),  # Determiner
                        Tree('NN', ['dog'])   # Singular noun
                    ]),
                    # Prepositional phrase (attached to NP - modifies noun)
                    # This attachment means: "the dog WITH the telescope"
                    Tree('PP', [
                        Tree('IN', ['with']),  # Preposition
                        # Object of preposition
                        Tree('NP', [
                            Tree('DT', ['the']),       # Determiner
                            Tree('NN', ['telescope'])  # Singular noun
                        ])
                    ])
                ])
            ])
        ])
        return tree
    
    # ========================================================================
    # TREE DISPLAY METHODS
    # ========================================================================
    
    def print_tree(self, tree_key):
        """
        Print a parse tree in both visual and bracketed notation.
        
        This method displays:
        1. A visual ASCII representation of the tree structure
        2. The bracketed notation (LISP-style representation)
        
        Args:
            tree_key (str): Key identifying which tree to print
                          ('sentence1', 'sentence2', 'sentence3_v1', 'sentence3_v2')
        """
        # Retrieve the tree from the dictionary
        tree = self.trees[tree_key]
        
        # Print header
        print(f"\n{'='*60}")
        print(f"Parse Tree: {tree_key}")
        print('='*60)
        
        # Display visual tree structure (ASCII art format)
        tree.pretty_print()
        
        # Display bracketed notation
        print("\nBracketed Notation:")
        print(tree)
        print()
    
    def visualize_tree_jupyter(self, tree_key):
        """
        Visualize tree in Jupyter notebook using matplotlib.
        
        This creates an inline visualization of the parse tree suitable
        for Jupyter notebooks.
        
        Args:
            tree_key (str): Key identifying which tree to visualize
        """
        tree = self.trees[tree_key]
        
        # Create a new figure
        fig, ax = plt.subplots(figsize=(12, 8))
        ax.axis('off')
        
        # Use NLTK's tree drawing functionality
        TreeView(tree)._cframe.print_to_file('temp_tree.ps')
        
        # Convert PostScript to displayable format
        from PIL import Image as PILImage
        import subprocess
        
        try:
            # Try to convert ps to png
            subprocess.run(['convert', 'temp_tree.ps', 'temp_tree.png'], 
                         check=True, capture_output=True)
            img = PILImage.open('temp_tree.png')
            plt.imshow(img)
            plt.axis('off')
            plt.title(f"Parse Tree: {tree_key}", fontsize=14, fontweight='bold')
            plt.tight_layout()
            plt.show()
            
            # Clean up temporary files
            if os.path.exists('temp_tree.ps'):
                os.remove('temp_tree.ps')
            if os.path.exists('temp_tree.png'):
                os.remove('temp_tree.png')
        except:
            # If conversion fails, just show the tree using draw()
            print(f"Graphical visualization for {tree_key}:")
            tree.draw()
    
    # ========================================================================
    # UTILITY METHODS
    # ========================================================================
    
    def get_sentence_from_tree(self, tree):
        """
        Extract the original sentence from a parse tree.
        
        This method retrieves all leaf nodes (terminal nodes/words) from the
        tree and joins them back into the original sentence.
        
        Args:
            tree (Tree): NLTK Tree object
        
        Returns:
            str: The original sentence reconstructed from tree leaves
        """
        # tree.leaves() returns all terminal nodes (words)
        return ' '.join(tree.leaves())
    
    def analyze_structure(self, tree_key):
        """
        Perform and display structural analysis of a parse tree.
        
        This method extracts and displays:
        1. The original sentence
        2. Tree height (maximum depth)
        3. Number of words (leaf nodes)
        4. Distribution of phrase types (how many of each constituent)
        5. All production rules (grammar rules used)
        
        Args:
            tree_key (str): Key identifying which tree to analyze
        """
        # Retrieve tree and reconstruct sentence
        tree = self.trees[tree_key]
        sentence = self.get_sentence_from_tree(tree)
        
        # Display basic information
        print(f"\n{'='*60}")
        print(f"Structural Analysis: {tree_key}")
        print('='*60)
        print(f"Sentence: {sentence}")
        print(f"Height: {tree.height()}")  # Maximum depth of tree
        print(f"Number of leaves (words): {len(tree.leaves())}")
        
        # Count phrase types using dictionary
        phrase_types = {}
        # tree.subtrees() returns all nodes (phrases and words)
        for subtree in tree.subtrees():
            label = subtree.label()  # Get node label (S, NP, VP, etc.)
            # Increment count for this phrase type
            phrase_types[label] = phrase_types.get(label, 0) + 1
        
        # Display phrase type distribution
        print("\nPhrase Type Distribution:")
        for phrase, count in sorted(phrase_types.items()):
            print(f"  {phrase}: {count}")
        
        # Extract and display production rules
        # Production rules show how each phrase expands (e.g., S -> NP VP)
        print("\nProduction Rules:")
        for production in tree.productions():
            print(f"  {production}")

print("✓ ParseTreeGenerator class defined successfully!")

# ============================================================================
# CELL 4: HELPER FUNCTIONS
# ============================================================================

def explain_pos_tags():
    """
    Print explanations for common POS (Part-of-Speech) tags.
    
    This reference guide helps users understand the meaning of various
    POS tags used in constituency parsing.
    """
    print("\n" + "="*60)
    print("COMMON POS TAG EXPLANATIONS")
    print("="*60)
    
    tags = {
        # Phrase-level (constituent) tags
        'S': 'Sentence (top-level clause)',
        'NP': 'Noun Phrase',
        'VP': 'Verb Phrase',
        'PP': 'Prepositional Phrase',
        
        # Word-level (terminal) tags
        'DT': 'Determiner (the, a, an)',
        'NN': 'Noun (singular)',
        'NNS': 'Noun (plural)',
        'VBD': 'Verb (past tense)',
        'VBZ': 'Verb (3rd person singular present)',
        'IN': 'Preposition or subordinating conjunction',
        'JJ': 'Adjective',
        'RB': 'Adverb'
    }
    
    for tag, description in tags.items():
        print(f"  {tag:5s} - {description}")


def demonstrate_pos_tagging():
    """
    Demonstrate automatic Part-of-Speech (POS) tagging using NLTK.
    
    This function shows how NLTK can automatically analyze sentences and
    assign POS tags to each word.
    """
    print("\n" + "="*60)
    print("AUTOMATIC POS TAGGING DEMONSTRATION")
    print("="*60)
    
    sentences = [
        "The government raised interest rates.",
        "The internet gives everyone a voice.",
        "The man saw the dog with the telescope."
    ]
    
    for sent in sentences:
        tokens = nltk.word_tokenize(sent)
        pos_tags = nltk.pos_tag(tokens)
        
        print(f"\nSentence: {sent}")
        print("POS Tags:")
        for word, tag in pos_tags:
            print(f"  {word:15s} -> {tag}")

print("✓ Helper functions defined successfully!")

# ============================================================================
# CELL 5: RUN COMPLETE DEMONSTRATION
# ============================================================================

def run_complete_demo():
    """
    Run the complete demonstration of parse tree analysis.
    """
    # Initialize parser
    parser = ParseTreeGenerator()
    
    # Show POS tag explanations
    explain_pos_tags()
    
    # Demonstrate automatic POS tagging
    demonstrate_pos_tagging()
    
    # Analyze each sentence
    print("\n" + "="*60)
    print("PARSE TREE ANALYSIS - SENTENCE 1")
    print("="*60)
    parser.print_tree("sentence1")
    parser.analyze_structure("sentence1")
    
    print("\n" + "="*60)
    print("PARSE TREE ANALYSIS - SENTENCE 2")
    print("="*60)
    parser.print_tree("sentence2")
    parser.analyze_structure("sentence2")
    
    # Show ambiguous sentence with both interpretations
    print("\n" + "="*60)
    print("AMBIGUOUS SENTENCE - TWO INTERPRETATIONS")
    print("="*60)
    
    print("\n" + "-"*60)
    print("INTERPRETATION 1: PP attached to VP")
    print("(The man used the telescope to see the dog)")
    print("-"*60)
    parser.print_tree("sentence3_v1")
    parser.analyze_structure("sentence3_v1")
    
    print("\n" + "-"*60)
    print("INTERPRETATION 2: PP attached to NP")
    print("(The dog has the telescope)")
    print("-"*60)
    parser.print_tree("sentence3_v2")
    parser.analyze_structure("sentence3_v2")
    
    print("\n" + "="*60)
    print("✓ DEMONSTRATION COMPLETE!")
    print("="*60)
    print("\nTo visualize trees graphically, run:")
    print("  parser = ParseTreeGenerator()")
    print("  parser.visualize_tree_jupyter('sentence1')")

print("✓ Demo function ready!")
print("\nTo run the complete demonstration, execute:")
print("  run_complete_demo()")

# ============================================================================
# CELL 6: QUICK START - RUN THIS TO SEE EVERYTHING
# ============================================================================

# Uncomment the line below to run the complete demonstration:
# run_complete_demo()

print("\n" + "="*60)
print("READY TO USE!")
print("="*60)
print("\nQuick Start Commands:")
print("1. Run complete demo:     run_complete_demo()")
print("2. Create parser:         parser = ParseTreeGenerator()")
print("3. Show specific tree:    parser.print_tree('sentence1')")
print("4. Analyze tree:          parser.analyze_structure('sentence1')")
print("5. Visualize tree:        parser.visualize_tree_jupyter('sentence1')")
print("\nAvailable trees: 'sentence1', 'sentence2', 'sentence3_v1', 'sentence3_v2'")
