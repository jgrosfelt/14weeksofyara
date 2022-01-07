# This code is heavily based on the python code created by Thomas Roccia, from here
# https://medium.com/malware-buddy/fifty-shades-of-malware-strings-d33b0c7bee99.
#
# My modifications include focusing purly on the intersection (not the union) and then 
# combining the intersection of strings for each file together


import argparse
import os
from nltk.tokenize import sent_tokenize, word_tokenize
from nltk.stem import PorterStemmer


#extract strings from files
def getstrings(fullpath):
    """
    Extract strings from the binary indicated by the 'fullpath'
    parameter, and then return the set of unique strings in
    the binary.
    """
    strings = os.popen("strings '{0}'".format(fullpath)).read()
    return strings


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="Identify similarities between malware samples and build similarity graph"
    )

    parser.add_argument(
        "target_directory",
        help="Directory containing malware"
    )

    args = parser.parse_args()
    malware_paths = [] # where we'll store the malware file paths
    malware_attributes = dict() # where we'll store the malware strings
    
    for root, dirs, paths in os.walk(args.target_directory):
        # walk the target directory tree and store all of the file paths
        for path in paths:
            full_path = os.path.join(root,path)
            malware_paths.append(full_path)


    # get and store the strings for all of the malware PE files
    for path in malware_paths:

        attributes = getstrings(path)
        print ("Extracted {0} attributes from {1} ...".format(len(attributes),path))
        tokenized=word_tokenize(attributes)
        stemmer = PorterStemmer()
        stemmed_words = [stemmer.stem(word) for word in tokenized]
        #print(stemmed_words)
        malware_attributes[path] = set(stemmed_words)
     # iterate through all pairs of malware
    
    final=None
    for path,attributes in malware_attributes.items():
        if final == None:
            final=attributes
        else:
            final=final&attributes
    final=list(final)
    print(final)
    for s in final:
        print(s)

