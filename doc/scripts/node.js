const fs = require('fs');
const yaml = require('js-yaml');
const path = require('path');


const outputDir = "D:\\Github\\bestsub\\test\\";


fs.mkdirSync(outputDir, { recursive: true });
const yamlFile = path.join(outputDir, 'bestsub_temp_proxies.yaml');

const tempDir = require('os').tmpdir();
const jsonFile = path.join(tempDir, 'bestsub_temp_proxies.json');


const fieldsToProcess = {
    'netflix': 'N',
    'youtube': 'Y',
    'chatgpt': 'O',
    'disney': 'D'
};

try {
    const jsonContent = fs.readFileSync(jsonFile, 'utf8');
    const data = JSON.parse(jsonContent);

    if (data.proxies && Array.isArray(data.proxies)) {
        data.proxies.forEach(proxy => {
            if (proxy.name) {
                let nameSuffix = '';

                for (const [field, marker] of Object.entries(fieldsToProcess)) {
                    if (proxy[field] === true) {
                        console.log(`${proxy.name}: ${field}=${proxy[field]} -> Adding marker ${marker}`);
                        nameSuffix += `-${marker}`;
                    }
                }

                if (nameSuffix) {
                    const oldName = proxy.name;
                    proxy.name = proxy.name + nameSuffix;
                    console.log(`Renamed: ${oldName} -> ${proxy.name}`);
                }

                for (const field of Object.keys(fieldsToProcess)) {
                    delete proxy[field];
                }

                delete proxy.country;
                delete proxy.speed;
            }
        });
    }

    const yamlContent = yaml.dump(data, {
        indent: 2,
        lineWidth: -1,
        quotingType: '"',
        forceQuotes: true
    });

    fs.writeFileSync(yamlFile, yamlContent, 'utf8');

    console.log('Successfully converted JSON to YAML');
    console.log(`YAML file saved at: ${yamlFile}`);
    console.log(`Processed ${data.proxies ? data.proxies.length : 0} proxies`);

} catch (error) {
    console.error('Error converting JSON to YAML:', error.message);
    process.exit(1);
} 