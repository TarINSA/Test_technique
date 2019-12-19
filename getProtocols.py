import subprocess
import csv
import glob

def getFiles():
    filesPCAP = glob.glob('*.pcap') #on recupere les noms des fichiers .pcap du dossier courant
    filesPCAPNG = glob.glob('*.pcapng') #on recupere les noms des fichiers .pcapng du dossier courant
    allFiles = filesPCAP + filesPCAPNG
    return allFiles

def readPacket(file):
    listOutput=[]
    #on constuit la commande pour lire les 50000 premiers paquets du fichier et ne retenir que les protocoles de ces paquets
    cmd = 'tshark -r '+file+' -c 50000 -T fields -e frame.protocols'
    #on lance la commande
    p = subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,encoding='ascii')
    output,error=p.communicate()
    if output:
        output=output.split('\n') #on decoupe le resultat grace aux fins de lignes
        for line in output:
            if line!='' and line not in listOutput: #on enleve les lignes vides et les protocoles deja presents
                listOutput.append(line)
        return listOutput
    if error:
        print("Une erreur s'est produite lors de la lecture du fichier : "+file)
        return []

def main():
    listFiles=getFiles() #on recupere tous les noms des fichiers de captures reseaux du repertoire courant
    try:
        with open('listeProtocoles.csv',mode='w') as writingFile:
            fileWriter = csv.writer(writingFile,delimiter=',')
            for file in listFiles:
                listProtocol=readPacket(file)
                if listProtocol!=[]:
                    #on ecrit les resultats dans le fichier listeProtocoles.csv en commencant par le nom du fichier suivi des protocoles presents dans le fichier (separes par des ,)
                    listProtocol.insert(0,file)
                    fileWriter.writerow(listProtocol)
    except IOError:
        print("Erreur lors de l'ouverture du fichier")

if __name__ == "__main__":
    main()
