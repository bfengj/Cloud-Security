import React, { useState } from "react";
import { S3 } from 'aws-sdk';
import dotenv from 'dotenv';

dotenv.config();

const FileUpload = () => {
    const [selectedFile, setSelectedFile] = useState(null);

    const handleFileInput = (event) => {
        setSelectedFile(event.target.files[0]);
    };

    const handleUpload = async () => {
        const s3 = new S3({
            accessKeyId: process.env.REACT_APP_AWS_ACCESS_KEY,
            secretAccessKey: process.env.REACT_APP_AWS_SECRET_ACCESS_KEY,
            region: process.env.REACT_APP_AWS_REGION
        });

        const params = {
            Bucket: process.env.REACT_APP_AWS_BUCKET_NAME,
            Key: selectedFile.name,
            Body: selectedFile
        };

        try {
            const uploadResponse = await s3.upload(params).promise();
            console.log(`File uploaded successfully at ${uploadResponse.Location}`);
        } catch (error) {
            console.error(error);
        }
    };

    return (
        <div>
            <input type="file" onChange={handleFileInput} />
            <button onClick={handleUpload}>Upload</button>
        </div>
    );
};

export default FileUpload;

