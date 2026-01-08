#include <cstdio>
#include <string>       
#include <vector>
#include <map>
#include <filesystem>
bool load_utf8_file(const std::string& filename, std::vector<char>& buffer) {
    // open the file in binary mode
    FILE* file = nullptr;
    errno_t err = fopen_s(&file, filename.c_str(), "rb");
    if (err != 0 || !file) {
        return false;
    }
    // seek to the end to determine file size
    std::fseek(file, 0, SEEK_END);
    long file_size = std::ftell(file);
    std::fseek(file, 0, SEEK_SET);
    // resize buffer to hold file content
    buffer.resize(file_size);
    // read file content into buffer
    size_t read_size = std::fread(buffer.data(), 1, file_size, file);
    std::fclose(file);
    if (read_size != static_cast<size_t>(file_size)) {
        return false;
    }
    return true;
}
bool writeback_utf8_file(const std::string& filename, const std::vector<char>& buffer) {
    // open the file in binary write mode
    FILE* file = nullptr;
    errno_t err = fopen_s(&file, filename.c_str(), "wb");
    if (err != 0 || !file) {
        return false;
    }
    // write buffer content to file
    size_t write_size = std::fwrite(buffer.data(), 1, buffer.size(), file);
    std::fclose(file);
    if (write_size != buffer.size()) {
        return false;
    }
    return true;
}
void print_vector(const std::vector<char>& buffer) {
    for (char c : buffer) {
        std::putchar(c);
    }
}
bool replace_in_vector(std::vector<char>& buffer, size_t a, size_t b, const std::string& replacement) { //[a,b)
    if (a > b || b > buffer.size()) {
        return false;
    }
    size_t original_size = b - a;
    size_t replacement_size = replacement.size();
    size_t buffer_sz=buffer.size();
    if (replacement_size > original_size) {
        buffer.resize(buffer_sz + (replacement_size - original_size));
        for(size_t i=buffer_sz-1;i>=b;i--){
            buffer[i + (replacement_size - original_size)] = buffer[i];
        }
        for(size_t i=0;i<replacement_size;i++){
            buffer[a + i] = replacement[i];
        }
        return true;
    }else if (replacement_size < original_size) {
        for (size_t i=0;i<replacement_size;i++){
            buffer[a + i] = replacement[i];
        }
        for (size_t i=b;i<buffer.size();i++){
            buffer[i-(original_size - replacement_size)] = buffer[i];
        }
        buffer.resize(buffer.size() - (original_size - replacement_size));
        return true;
    }else{
        for (size_t i = 0; i < replacement_size; ++i) {
            buffer[a + i] = replacement[i];
        }
        return true;
    }

    return true;
}
void string_to_vector(const std::string& str, std::vector<char>& buffer) {
    buffer.resize(str.size());
    for (size_t i = 0; i < str.size(); ++i) {
        buffer[i] = str[i];
    }
}

std::vector<std::pair<size_t, size_t>> find_in_vector_from_to(const std::vector<char>& buffer, const std::string& target, size_t from, size_t to) {
    size_t buffer_size = buffer.size();
    size_t target_size = target.size();
    std::vector<std::pair<size_t, size_t>> results;
    for (size_t i = from; i <= to - target_size; ++i) {
        bool match = true;
        for (size_t j = 0; j < target_size; ++j) {
            
            if (buffer[i + j] != target[j]) {
                match = false;
                break;
            }
        }
        if (match) {
            results.push_back({i, i + target_size});
        }
    }
    return results;
}
bool match_in_vector_at(const std::vector<char>& buffer, const std::string& target, size_t pos) {
    size_t buffer_size = buffer.size();
    size_t target_size = target.size();
    if (pos + target_size > buffer_size) {
        return false;
    }
    for (size_t j = 0; j < target_size; ++j) {
        if (buffer[pos + j] != target[j]) {
            return false;
        }
    }
    return true;
}
struct PatternResult {
    bool found;
    size_t start;
    size_t end;
    std::vector<std::string> placeholders;
};
struct Pattern {
    std::vector<std::string> parts; // parts between placeholders
    struct Placeholder {
        size_t index; // index of the placeholder
        std::string matchchars;// characters that can match this placeholder
    };
    std::vector<Placeholder> placeholders; // list of placeholders
};
bool is_char_in_string(char c, const std::string& str) {
    for (char sc : str) {
        if (c == sc) {
            return true;
        }
    }
    return false;
}
bool find_pattern_in_vector(const std::vector<char>& buffer, Pattern pattern,PatternResult* result, size_t patternid=0,size_t last_pattern_end=0) {
    if (patternid>=pattern.parts.size()) {
        result->found=true;
        result->end=last_pattern_end;
        return true;
    }
    bool ret=false;
    if(!patternid){
        result->found=false;
        std::vector<std::pair<size_t, size_t>> finded=find_in_vector_from_to(buffer,pattern.parts[patternid],last_pattern_end,buffer.size());
        for(std::pair<size_t, size_t> p:finded){
            //printf("Found part %zu at %zu to %zu\n",patternid,p.first,p.second);
            //clear previous placeholders
            if (result->found) {
                return true;
            }
            result->start=p.first;
            result->placeholders.clear();
            ret=ret||find_pattern_in_vector(buffer,pattern,result,patternid+1,p.second);
        }
    }else{
        size_t pos;
        std::string placeholder_match="";
        for(pos=last_pattern_end;is_char_in_string(buffer[pos], pattern.placeholders[patternid-1].matchchars)&&pos<=buffer.size()-pattern.parts[patternid].size();pos++){
            placeholder_match+=buffer[pos];
        }
        if(match_in_vector_at(buffer,pattern.parts[patternid],pos)){
            //printf("Found part %zu at %zu to %zu\n",patternid,pos,pos+pattern.parts[patternid].size());
            if (result->placeholders.size()<=pattern.placeholders[patternid-1].index){
                result->placeholders.resize(pattern.placeholders[patternid-1].index+1);
            }
            //if not match previous placeholder,continue
            if(result->placeholders[pattern.placeholders[patternid-1].index]!=""){
                if(result->placeholders[pattern.placeholders[patternid-1].index]!=placeholder_match){
                    return false;
                }
            }else{
                result->placeholders[pattern.placeholders[patternid-1].index]=placeholder_match;
            }
            ret=ret||find_pattern_in_vector(buffer,pattern,result,patternid+1,pos+pattern.parts[patternid].size());
        }
    }
    return ret;
}
void legacyworld(std::vector<char>& buffer) {
    Pattern pattern;
    pattern.parts.push_back("r.createElement(l.Mount,{when:e},r.createElement(");
    pattern.placeholders.push_back(Pattern::Placeholder{0,"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_$."});
    pattern.parts.push_back(",null,r.createElement(");
    pattern.placeholders.push_back(Pattern::Placeholder{1,"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_$."});
    pattern.parts.push_back(",{label:i(\".generatorTypeLabel\"),options:[{value:");
    pattern.placeholders.push_back(Pattern::Placeholder{2,"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_$"});
    pattern.parts.push_back(".Overworld,label:i(\".vanillaWorldGeneratorLabel\"),description:i(\".vanillaWorldGeneratorDescription\")},{value:");
    pattern.placeholders.push_back(Pattern::Placeholder{2,"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_$"});
    pattern.parts.push_back(".Flat,label:i(\".flatWorldGeneratorLabel\"),description:i(\".flatWorldGeneratorDescription\")},{value:");
    pattern.placeholders.push_back(Pattern::Placeholder{2,"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_$"});
    pattern.parts.push_back(".Void,label:i(\".voidWorldGeneratorLabel\"),description:i(\".voidWorldGeneratorDescription\")}],value:");
    pattern.placeholders.push_back(Pattern::Placeholder{3,"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_$"});
    pattern.parts.push_back(".value,onChange:");
    pattern.placeholders.push_back(Pattern::Placeholder{3,"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_$"});
    pattern.parts.push_back(".onChange})))");
    PatternResult result;
    if(!find_pattern_in_vector(buffer,pattern,&result)){
        printf("legacyworld pattern not found\n");
        return;
    }
    std::string replacement="r.createElement("+result.placeholders[0]+",null,r.createElement("+result.placeholders[1]+",{label:i(\".generatorTypeLabel\"),options:[{value:"+result.placeholders[2]+".Overworld,label:i(\".vanillaWorldGeneratorLabel\"),description:i(\".vanillaWorldGeneratorDescription\")},{value:"+result.placeholders[2]+".Flat,label:i(\".flatWorldGeneratorLabel\"),description:i(\".flatWorldGeneratorDescription\")},{value:"+result.placeholders[2]+".Void,label:i(\".voidWorldGeneratorLabel\"),description:i(\".voidWorldGeneratorDescription\")},{value:"+result.placeholders[2]+".Legacy,label:i(\".legacyWorldGeneratorLabel\"),description:i(\".legacyWorldGeneratorDescription\")}],value:"+result.placeholders[3]+".value,onChange:"+result.placeholders[3]+".onChange}))";
    printf("Replacement: %s\n",replacement.c_str());
    replace_in_vector(buffer,result.start,result.end,replacement);
}
//(e=>e?[{label:".debugTabLabel",image:#A3#.DebugIcon,value:"debug"}]:[])
void debugsection(std::vector<char>& buffer){
    Pattern pattern;
    pattern.parts.push_back("(e=>e?[{label:\".debugTabLabel\",image:");
    pattern.placeholders.push_back(Pattern::Placeholder{0,"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_$"});
    pattern.parts.push_back(".DebugIcon,value:\"debug\"}]:[])");
    PatternResult result;
    if(!find_pattern_in_vector(buffer,pattern,&result)){
        printf("debugsection pattern not found\n");
        return;
    }
    std::string replacement="(e=>[{label:\".debugTabLabel\",image:"+result.placeholders[0]+".DebugIcon,value:\"debug\"}])";
    printf("Replacement: %s\n",replacement.c_str());
    replace_in_vector(buffer,result.start,result.end,replacement);
}
void offlineservers(std::vector<char>& buffer){
    //(!#A5#.isLoggedInWithMicrosoftAccount||#A5#.userPermissions.multiplayer.denyReasons.includes(#A4#.XboxLive)||#A6#&&!#A5#.hasPremiumNetworkAccess)
    Pattern pattern;
    pattern.parts.push_back("(!");
    pattern.placeholders.push_back(Pattern::Placeholder{0,"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_$"});
    pattern.parts.push_back(".isLoggedInWithMicrosoftAccount||");
    pattern.placeholders.push_back(Pattern::Placeholder{0,"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_$"});
    pattern.parts.push_back(".userPermissions.multiplayer.denyReasons.includes(");
    pattern.placeholders.push_back(Pattern::Placeholder{1,"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_$"});
    pattern.parts.push_back(".XboxLive)||");
    pattern.placeholders.push_back(Pattern::Placeholder{2,"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_$"});
    pattern.parts.push_back("&&!");
    pattern.placeholders.push_back(Pattern::Placeholder{0,"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_$"});
    pattern.parts.push_back(".hasPremiumNetworkAccess)");
    PatternResult result;
    if(!find_pattern_in_vector(buffer,pattern,&result)){
        printf("offlineservers pattern not found\n");
        return;
    }
    replace_in_vector(buffer,result.start,result.end,"false");
}
void signoutfix(std::vector<char>& buffer){
    Pattern pattern;
    pattern.parts.push_back("===");//parts cannot contain #
    pattern.placeholders.push_back(Pattern::Placeholder{0,"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_$"});
    pattern.parts.push_back(".UWP_GDK_PC||");
    pattern.placeholders.push_back(Pattern::Placeholder{1,"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_$"});
    pattern.parts.push_back("===");//parts cannot contain #
    pattern.placeholders.push_back(Pattern::Placeholder{0,"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_$"});
    pattern.parts.push_back(".XBOX||");
    pattern.placeholders.push_back(Pattern::Placeholder{2,"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_$"});
    pattern.parts.push_back(".isInGame||");
    pattern.placeholders.push_back(Pattern::Placeholder{3,"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_$"});
    pattern.parts.push_back(".push({label:");
    pattern.placeholders.push_back(Pattern::Placeholder{4,"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_$"});
    pattern.parts.push_back("(\".signOut\")");
    PatternResult result;
    if(!find_pattern_in_vector(buffer,pattern,&result)){
        printf("signoutfix pattern not found\n");
        return;
    }
    std::string replacement="==="+result.placeholders[0]+".XBOX||"+result.placeholders[2]+".isInGame||"+result.placeholders[3]+".push({label:"+result.placeholders[4]+"(\".signOut\")";
    printf("Replacement: %s\n",replacement.c_str());
    replace_in_vector(buffer,result.start,result.end,replacement);
}/**/
void apply_patches(std::vector<char>& buffer) {
    legacyworld(buffer);
    debugsection(buffer);
    offlineservers(buffer);
    signoutfix(buffer);
}
void patch_file(const std::string& filename) {
    std::vector<char> buffer;
    if (!load_utf8_file(filename, buffer)) {
        std::fprintf(stderr, "Failed to load file: %s\n", filename.c_str());
        return;
    }
    apply_patches(buffer);
    if (!writeback_utf8_file(filename, buffer)) {
        std::fprintf(stderr, "Failed to write back file: %s\n", filename.c_str());
        return;
    }
    std::printf("Patched file successfully: %s\n", filename.c_str());
}
int oreuifix() {
    std::vector<std::string> files_to_patch;
    const std::string directory = "data/gui/dist/hbui/";
    for (const auto& entry : std::filesystem::directory_iterator(directory)) {
        const std::string filename = entry.path().filename().string();
        if (filename.rfind("index", 0) == 0 && filename.size() > 6 && filename.substr(filename.size() - 3) == ".js") {
            files_to_patch.push_back(entry.path().string());
        }
    }
    for (const std::string& filename : files_to_patch) {
        patch_file(filename);
    }
    return 0;
}
