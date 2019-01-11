#include <iostream>
#include <fstream>
#include <vector>
#include <map>
#include <cstdlib>

using namespace std;

struct Seg {
    int num;
    Seg(unsigned char s){
        num = (int)s;
    };
    Seg() {
        num = -1;
    }
};

typedef struct Seg Seg;

struct TLV {
    Seg type;
    vector<Seg> length;
    vector<Seg> value;
};

typedef struct TLV TLV;

struct SignatureAlgorithm {
    TLV algorithm;
    TLV parameters;
};

struct subjectPublicKey {
    TLV algorithm;
    TLV parameters;
    TLV PKey;
};

struct SignatureValue {
    TLV signatureValue;
};

struct signatureArray {
    TLV s1, s2;
};

typedef struct SignatureAlgorithm SignatureAlgorithm;
typedef struct subjectPublicKey subjectPublicKey;
typedef struct SignatureValue SignatureValue;
typedef struct signatureArray signatureArray;

struct TbsCertificate{
    TLV version;
    TLV serialNumber;
    SignatureAlgorithm signature;
    vector<signatureArray> issuer_;
    vector<TLV> validity;
    vector<signatureArray> subject_;
    subjectPublicKey subjectPublicKeyInfo;
    TLV issuerUniqueID;
    TLV subjectUniqueID;
    vector<TLV> extensions;
};

struct X509cer {
    struct TbsCertificate catb;
    struct SignatureAlgorithm casa;
    struct SignatureValue casv;
};

class X509Reader {
private:
    vector<Seg> segList;
    vector<TLV> tlvList;
    struct X509cer x509cert;
    map<string, string> OIDMap;
public:
    X509Reader() {
        OIDMap.insert(pair<string, string>("1.2.840.10040.4.1","DSA"));
        OIDMap.insert(pair<string, string>("1.2.840.10040.4.3","sha1DSA"));
        OIDMap.insert(pair<string, string>("1.2.840.113549.1.1.1","RSA"));
        OIDMap.insert(pair<string, string>("1.2.840.113549.1.1.2","md2RSA"));
        OIDMap.insert(pair<string, string>("1.2.840.113549.1.1.3","md4RSA"));
        OIDMap.insert(pair<string, string>("1.2.840.113549.1.1.4","md5RSA"));
        OIDMap.insert(pair<string, string>("1.2.840.113549.1.1.5","sha1RSA"));
        OIDMap.insert(pair<string, string>("1.2.840.113549.1.1.11","sha256RSA"));
        OIDMap.insert(pair<string, string>("1.2.840.10045.2.1","ECC"));
        OIDMap.insert(pair<string, string>("1.2.840.10045.3.1.7","ECDSA_P256"));

        OIDMap.insert(pair<string, string>("2.5.4.6","C"));
        OIDMap.insert(pair<string, string>("2.5.4.8","S"));
        OIDMap.insert(pair<string, string>("2.5.4.7","L"));
        OIDMap.insert(pair<string, string>("2.5.4.10","O"));
        OIDMap.insert(pair<string, string>("2.5.4.11","OU"));
        OIDMap.insert(pair<string, string>("2.5.4.3","CN"));
    }
    void loadFile(string filename) {
        std::ifstream file;
        file.open(filename.c_str(), ios::in|ios::binary);
        while(!file.eof()) {
            char first;
            file.read(&first, 1);
            segList.push_back(Seg((unsigned char)first));
        }
        file.close();
    }

    void compileContent() {
        for(int i = 0; i < segList.size(); ) {
            if(segList[i].num >> 6 == 2) {
                int n = segList[i].num & 0x1f;
                if(n == 3) {
                    TLV t;
                    t.type = segList[i];
                    if(segList[i+1].num <= 0x7f) {
                        t.length.push_back(segList[i+1]);
                        i += 2;
                    }
                    else {
                        int l = segList[i+1].num-0x80;
                        int s = 0, base = 1;
                        for(int j = i+2+l-1; j >= i+2; j--) {
                            s += segList[j].num * base;
                            base *= 256;
                        }
                        for(int j = i+1; j < i+2+l; j++) {
                            t.length.push_back(segList[j]);
                        }
                        i += 2+l;
                    }
                    tlvList.push_back(t);
                }
                else {
                    TLV t;
                    t.type = segList[i];
                    t.length.push_back(segList[i+1]);
                    tlvList.push_back(t);
                    i += 2;
                }
            }
            else {
                if(segList[i].num >> 5 == 1) {
                    TLV t;
                    t.type = segList[i];
                    if(segList[i+1].num <= 0x7f) {
                        t.length.push_back(segList[i+1]);
                        i += 2;
                    }
                    else {
                        int l = segList[i+1].num-0x80;
                        int s = 0, base = 1;
                        for(int j = i+2+l-1; j >= i+2; j--) {
                            s += segList[j].num * base;
                            base *= 256;
                        }
                        for(int j = i+1; j < i+2+l; j++) {
                            t.length.push_back(segList[j]);
                        }
                        i += 2+l;
                    }
                    tlvList.push_back(t);
                }
                else {
                    TLV t;
                    t.type = segList[i];
                    if(segList[i+1].num <= 0x7f) {
                        t.length.push_back(segList[i+1]);
                        for(int j = i+2; j < i+2+segList[i+1].num; j++) {
                            t.value.push_back(segList[j]);
                        }
                        i += segList[i+1].num + 2;
                    }
                    else {
                        int l = segList[i+1].num-0x80;
                        int s = 0, base = 1;
                        for(int j = i+2+l-1; j >= i+2; j--) {
                            s += segList[j].num * base;
                            base *= 256;
                        }
                        for(int j = i+1; j < i+2+l; j++) {
                            t.length.push_back(segList[j]);
                        }
                        for(int j = i+2+l; j < i+2+l+s; j++) {
                            t.value.push_back(segList[j]);
                        }
                        i += 2+l+s;
                    }
                    tlvList.push_back(t);
                }
            }
        }
    }

    void showX509() {
        int count = 0, extensionSize = 0;
        bool isExtension = false;
        bool isBlock31 = false;
        for(int i = 0; i < tlvList.size()-1; i++) {
            if(isExtension){
                extensionSize -= 1 + tlvList[i].length.size() +  tlvList[i].value.size();
            }
            if(tlvList[i].type.num == 0x31) {
                isBlock31 = true;
                continue;
            }
            else {
                if(tlvList[i].type.num == 0x30 && isBlock31 == false) {
                    count++;
                    continue;
                }
                else if(tlvList[i].type.num == 0x30 && isBlock31 == true) {
                    isBlock31 = false;
                    continue;
                }
                else if(tlvList[i].type.num == 0xa3) {
                    count++;
                    isExtension = true;
                    int base = 1;
                    for(int j = tlvList[i].length.size()-1; j >= 1; j--){
                        extensionSize += tlvList[i].length[j].num * base;
                        base *= 256;
                    }
                    continue;
                }
            }
            if(count == 2) {
                if(tlvList[i].type.num == 0xa0) {
                    x509cert.catb.version = tlvList[i+1];
                    i++;
                }
                else{
                    x509cert.catb.serialNumber = tlvList[i];
                }
            }
            else if(count == 3) {
                if(tlvList[i].type.num == 0x06) {
                    x509cert.catb.signature.algorithm = tlvList[i];
                }
                else {
                    x509cert.catb.signature.parameters = tlvList[i];
                }
            }
            else if(count == 4) {
                signatureArray a;
                if(tlvList[i].type.num == 0x06) {
                    a.s1 = tlvList[i];
                    a.s2 = tlvList[i+1];
                    x509cert.catb.issuer_.push_back(a);
                    i+=1;
                }
            }
            else if(count == 5) {
                x509cert.catb.validity.push_back(tlvList[i]);
                x509cert.catb.validity.push_back(tlvList[i+1]);
                i+=1;
            }
            else if(count == 6) {
                signatureArray a;
                if(tlvList[i].type.num == 0x06) {
                    a.s1 = tlvList[i];
                    a.s2 = tlvList[i+1];
                    x509cert.catb.subject_.push_back(a);
                    i+=1;
                }
            }
            else if(count == 8) {
                if(tlvList[i].type.num == 0x06) {
                    subjectPublicKey sbk;
                    sbk.algorithm = tlvList[i];
                    sbk.parameters = tlvList[i+1];
                    sbk.PKey = tlvList[i+2];
                    x509cert.catb.subjectPublicKeyInfo = sbk;
                    i+=2;
                }
            }
            else if(count >= 9 && isExtension) {
                if(extensionSize >= 0) {
                    x509cert.catb.extensions.push_back(tlvList[i]);
                }
                if(extensionSize == 0) {
                    isExtension = false;
                }
            }
            else {
                if(tlvList[i].type.num == 0x06) {
                    x509cert.casa.algorithm = tlvList[i];
                    x509cert.casa.parameters = tlvList[i+1];
                    x509cert.casv.signatureValue = tlvList[i+2];
                    i += 2;
                }
            }
        }
    }

    string formatDate(TLV& p) {
        string result = "20";
        if(p.type.num == 0x17) {
            int count = 0;
            for(int i = 0; i < p.value.size()-1; i+=2){
                result = result + (char)p.value[i].num + (char)p.value[i+1].num;
                if(count <= 1){
                    result += "/";
                }
                else if(count == 2) {
                    result += " ";
                }
                else if(count <= 4){
                    result += ":";
                }
                count++;
            }
            return result + " GMT";
        }
        else {
            return "";
        }
    }

    string formatOID(TLV& p) {
        string result = "";
        char num[9];
        vector<int> V;
        if(p.type.num == 0x06) {
            for(int i = 0; i < p.value.size(); i++){
                if(i == 0) {
                    int v2 = p.value[i].num % 40;
                    int v1 = (p.value[i].num -v2) / 40;
                    V.push_back(v1);
                    V.push_back(v2);
                }
                else {
                    int j = i, res = 0;
                    int base = 128;
                    while(p.value[j].num >= 0x80){
                        j++;
                    }
                    res = p.value[j].num;
                    for(int k = j-1; k >= i; k--) {
                        res += (p.value[k].num - 0x80) * base;
                        base *= 128;
                    }
                    V.push_back(res);
                    i = j;
                }
            }
            for(int i = 0; i < V.size(); i++) {
                sprintf(num, "%d",V[i]);
                result += num;
                if(i < V.size()-1){
                    result += ".";
                }
            }
            return OIDMap[result];
        }
        else {
            return "";
        }
    }

    void displayOrigin() {
        int count = 0;
        for(int i = 0; i < segList.size(); i++) {
            printf("%02x ", segList[i].num);
            count++;
            if(count == 16){
                cout << endl;
                count = 0;
            }
        }
    }

    void displayTLVOrigin() {
        int count = 0;
        bool isBlock31 = false;
        for(int i = 0; i < tlvList.size(); i++) {
            if(tlvList[i].type.num == 0x31) {
                isBlock31 = true;
            }
            else {
                if(tlvList[i].type.num == 0x30 && isBlock31 == false) {
                    count++;
                }
                else if(tlvList[i].type.num == 0x30 && isBlock31 == true) {
                    isBlock31 = false;
                }
                else if(tlvList[i].type.num == 0xa3){
                    count++;
                }
            }
            cout << "Count: " << count << endl;
            printf("type: %02x ", tlvList[i].type);
            printf("length: ");
            for(int j = 0; j < tlvList[i].length.size(); j++) {
                printf("%02x ", tlvList[i].length[j]);
            }
            printf("value(%02x): ", tlvList[i].value.size());
            for(int j = 0; j < tlvList[i].value.size(); j++) {
                printf("%02x ", tlvList[i].value[j]);
            }
            printf("\n");
        }
    }
    
    void printValue(TLV& p, int mode = 0) {
        if(p.value.size() == 0){
            printf("NULL");
        }
        else{
            for(int i = 0; i < p.value.size(); i++) {
                if(p.type.num == 0x03 && i == 0) continue;
                if(p.type.num == 0x13) {
                    printf("%c", p.value[i].num);
                }
                else {
                    if(mode == 0) {
                        printf("%02x ", p.value[i].num);
                    }
                    else{
                        printf("%02x", p.value[i].num);
                    }
                }
                
            }
            if (p.type.num == 0x0c) {
                printf("(UTF-8)");
            }
        }
        printf("\n");
    }

    void displayResult() {
        printf("Version: V%d\n", x509cert.catb.version.value[0].num+1);
        printf("SerialNumber: ");
        printValue(x509cert.catb.serialNumber, 1);
        printf("SignatureAlgorithm:\n    Algorithm: ");
        cout << formatOID(x509cert.catb.signature.algorithm) << endl;
        printf("    Params: ");
        printValue(x509cert.catb.signature.parameters);
        printf("Issuer: \n");
        for(int i = 0; i < x509cert.catb.issuer_.size(); i++) {
            cout << "    " << formatOID(x509cert.catb.issuer_[i].s1);
            printf(" = ");
            printValue(x509cert.catb.issuer_[i].s2);
        }
        printf("Validity:\n    notBefore: ");
        cout << formatDate(x509cert.catb.validity[0]) << endl;
        printf("    notAfter: ");
        cout << formatDate(x509cert.catb.validity[1]) << endl;
        printf("Subject:\n");
        for(int i = 0; i < x509cert.catb.subject_.size(); i++) {
            cout << "    " << formatOID(x509cert.catb.subject_[i].s1);
            printf(" = ");
            printValue(x509cert.catb.subject_[i].s2);
        }
        printf("subjectPublicKeyInfo:\n");
        printf("    Algorithm: ");
        cout << formatOID(x509cert.catb.subjectPublicKeyInfo.algorithm) << endl;
        printf("        Params: ");
        printValue(x509cert.catb.subjectPublicKeyInfo.parameters);
        printf("        PKey: ");
        printValue(x509cert.catb.subjectPublicKeyInfo.PKey);
        printf("issuerUniqueID: ");
        printValue(x509cert.catb.issuerUniqueID);
        printf("subjectUniqueID: ");
        printValue(x509cert.catb.subjectUniqueID);
        printf("Extensions:\n");
        printf("    Other: ellipsis\n");
        /*
        for(int i = 0; i < x509cert.catb.extensions.size(); i++) {
            if(x509cert.catb.extensions[i].type.num == 0x01) {
                printf("    isCACertification: ");
                printValue(x509cert.catb.extensions[i]);
                printf("    Other: ellipsis\n");
                break;
            }
        }*/
        printf("SignatureAlgorithm:\n");
        printf("    Algorithm: ");
        cout << formatOID(x509cert.casa.algorithm) << endl;
        printf("    Params: ");
        printValue(x509cert.casa.parameters);
        printf("SignatureValue: ");
        printValue(x509cert.casv.signatureValue);
    }
};

int main() {
    X509Reader reader;
    reader.loadFile("DER_x509.cer");
    //reader.displayOrigin();
    reader.compileContent();
    //reader.displayTLVOrigin();
    reader.showX509();
    reader.displayResult();
    return 0;
}
