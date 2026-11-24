import assert from 'node:assert/strict';
import {readFile,readdir} from 'node:fs/promises';
import {dirname,relative,resolve} from 'node:path';
import ts from 'typescript';

/** Checks copied consumer code before dependencies are installed; this is not an execution sandbox. */
export async function assertIndependentSdkImports(directory:string):Promise<void>{
 for(const name of (await readdir(directory,{recursive:true})).filter(name=>/\.(?:[cm]?[jt]s)$/.test(name))){
  const source=await readFile(resolve(directory,name),'utf8'),specifiers:string[]=[];
  const visit=(node:ts.Node)=>{
   if((ts.isImportDeclaration(node)||ts.isExportDeclaration(node))&&node.moduleSpecifier){
    assert(ts.isStringLiteral(node.moduleSpecifier));specifiers.push(node.moduleSpecifier.text);
   }else if(ts.isImportEqualsDeclaration(node)&&ts.isExternalModuleReference(node.moduleReference)){
    assert(node.moduleReference.expression&&ts.isStringLiteral(node.moduleReference.expression));specifiers.push(node.moduleReference.expression.text);
   }else if(ts.isCallExpression(node)&&node.expression.kind===ts.SyntaxKind.ImportKeyword){
    assert.equal(node.arguments.length,1);assert(ts.isStringLiteral(node.arguments[0]),'Consumer imports must name explicit modules');
    specifiers.push(node.arguments[0].text);
   }else if(ts.isImportTypeNode(node)){
    assert(ts.isLiteralTypeNode(node.argument)&&ts.isStringLiteral(node.argument.literal));specifiers.push(node.argument.literal.text);
   }
   ts.forEachChild(node,visit);
  };
  visit(ts.createSourceFile(name,source,ts.ScriptTarget.ES2023,true,ts.ScriptKind.TS));
  for(const specifier of specifiers){
   if(specifier.startsWith('.'))assert(!relative(directory,resolve(dirname(resolve(directory,name)),specifier)).startsWith('..'),
    `Consumer relative import escapes its project: ${name}: ${specifier}`);
   else assert(specifier.startsWith('node:')||specifier==='@ava-protocol/sdk'||specifier==='@ava-protocol/agent-sdk'||/^viem(?:\/accounts|\/chains)?$/.test(specifier),
    `Unsupported consumer import: ${name}: ${specifier}`);
  }
 }
}
